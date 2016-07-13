# Copyright (c) 2016, Centre for Advanced Internet Architectures,
# Swinburne University of Technology. All rights reserved.
#
# Author: Dzuy Pham (dhpham@swin.edu.au)
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# The views and conclusions contained in the software and documentation are those
# of the authors and should not be interpreted as representing official policies,
# either expressed or implied, of the FreeBSD Project.

"""Ryu Action Node - RYU based application

Usage
-----
ryu-manager ./ran.py

Information
-----------
- Compatible with ryu.app.simple_switch and ryu.app.rest_router running on Open
    vSwitch OpenFlow Table 2
- Supports Multi Version Switches
    - OpenFlow 1.3
    - OpenFlow 1.4
    - OpenFlow 1.5 (Limited, no meters)
- Supports Multiple Switches
- Support Multi FCN/CN Packets

"""
# Import internal libraries
try:
    import configparser as ConfigParser
except ImportError:
    import ConfigParser
import binascii
import socket
import struct
import copy
from datetime import datetime

# Import RYU required libraries
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_4
from ryu.ofproto import ofproto_v1_5

# Import RAN required libraries
from lib.diffuse_parse import ipv4_to_int
from lib.diffuse_parse import proto_check
from lib.packet_process import header_offset_check
from lib.packet_process import join
from lib.packet_process import msg_check
from lib.packet_process import template_check
from lib.ver_check import version_check


class RAN(app_manager.RyuApp):
    """Ryu Action Node Northbound Application

        - Parses 'Classifier Node' and 'Fake Classifier Node' based packets
        using the 'Remote Actions Protocol' (RAP).
        - Implements class based prioritisation set by a configuration file

    """
    # Supported OpenFlow Versions
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION,
                    ofproto_v1_4.OFP_VERSION,
                    ofproto_v1_5.OFP_VERSION]
    # Initialise meter variables
    config = None
    dscp_no = 0
    inst = None
    meter_id = None
    meters = []
    priority = None
    queue = 0
    rate = 0
    _type = 0
    timeout = None

    def __init__(self, *args, **kwargs):
        super(RAN, self).__init__(*args, **kwargs)

        # The supported RAN OpenFlow versions
        self.ofp_ver = ['OF13', 'OF14', 'OF15']

        # Contains the datapaths for each connected SDN switch
        self.datapaths = {}

        # Offset used to know location when parsing a RAP message.
        self.offset = 0

        # List of valid class names that have a configuration set, including a
        # required 'default' class
        self.class_name = self.import_conf()

        # Initialises the Diffuse Parser module to receive any RAP messages.
        self.parser_initialiser = hub.spawn(self.parser_initialiser)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, event):
        """Handles connection between RYU and the SDN Switches

        If the version of the SDN Switch is supported, create a rule on the
        SDN switch which:
        1. Sends all flow miss packets to the controller
        2. Sends non-matching flows to the the next table

        Parameters
        ----------
        event: instance of OFPSwitchFeatures()
            The event contains a msg class with a structure of the SDN switch
            features that was sent

        """
        # Get Event switch datapath
        datapath = event.msg.datapath
        # Get OpenFlow Version for connected switch
        ofp_ver = version_check(datapath.ofproto.OFP_VERSION)
        self.logger.debug("Highest OF Version Supported on Switch ID: %s : %s",
                          datapath.id, ofp_ver)

        # Add/Update Switch datapath into list of connected switches
        if datapath.id not in self.datapaths:
            self.datapaths[datapath.id] = datapath
        else:
            self.datapaths.update({datapath.id: datapath})

        table_id = 0  # RAN always in lowest table
        priority = 0  # Miss flows are the last to match

        # Create on flow-miss go to controller for compatible OpenFlow versions
        if ofp_ver != 0:
            self.add_flow_miss(datapath=datapath,
                               priority=priority,
                               table_id=table_id)
        else:
            self.logger.debug("Error: %s Unsupported Version '%s'",
                              ofp_ver, datapath.id)

        self.logger.debug('Datapath \'%s\'', self.datapaths)

    def parser_initialiser(self):
        """Initialises the parser for Fake Classifier Node and Classifier
        Nodes' RAP Protocol messages

        Raises
        ------
        RuntimeError:
            If there is a problem in the decoding of the message

        """
        # Initialise the socket to listen on host and port using TCP
        sock = self.listen_tcp_socket()
        self.logger.info("%s RAN initiated", self.time_now())
        while True:
            # Receive incoming messages
            decoded_msg, msg_count = self.receive_parsed_data(sock=sock)

            # Parse and implement message through RYU
            try:
                self.implement_parser(decoded_msg, msg_count)
            except RuntimeError:
                self.logger.error("Error: Trying once more")
                self.implement_parser(decoded_msg, msg_count)

    def listen_tcp_socket(self):
        """Create TCP socket and listen on that port

        Returns
        -------
        sock: object
            The created socket

        """
        host = ''  # Listen on localhost
        port = 5000  # Listen on port 5000

        # Create socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.logger.info('%s Socket created', self.time_now())

        # Connect to socket
        try:
            sock.bind((host, port))
        except socket.error:
            self.logger.error('%s Binding error', self.time_now())
            self.logger.error(
                '%s Socket in TIME-WAIT state, wait until socket is closed',
                self.time_now())
            exit(1)
        else:
            self.logger.info('%s Binding successful', self.time_now())

        # Listen to the socket
        try:
            sock.listen(1)
        except socket.error:
            self.logger.error(
                '%s Cannot listen on port %d', str(
                    datetime.now()), port)
        else:
            self.logger.info(
                '%s Socket now listening on port %d', str(
                    datetime.now()), port)
        return sock

    def implement_parser(self, parameter_sets, msg_count):
        """Implements parsed data depending on Msg Type

        MsgType : 0
            Send Add Flow to the SDN Switch
        MsgType : 1
            Send Delete matching 5-tuple IP Flows to the SDN Switch
        MsgType : 2
            Send Delete all IP Flows to the SDN Switch

        Parameters
        ----------
        parameter_sets: list of dicts
            The index of the list contains a dictionary containing a set of
            Action Parameters
        msg_count: int
            The number of sets of in the decoded msg

        """
        for d_n, datapath_key in enumerate(self.datapaths):
            # Import most recent 'Datapath' of switch and their functions
            datapath = self.datapaths[datapath_key]
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser

            # Check if the switch's datapath is compatible
            max_ver = version_check(datapath.ofproto.OFP_VERSION)

            if max_ver not in self.ofp_ver:
                continue

            for msg_index in range(0, msg_count, 1):
                # Get current set of action parameters from the received
                # message
                flow_set = parameter_sets[msg_index]

                # Check if the switch's datapath is compatible
                max_ver = version_check(datapath.ofproto.OFP_VERSION)

                load = self.msg_converter(flow_set=flow_set,
                                          max_ver=max_ver)

                # ClassName Conversion
                class_name = flow_set['CLASS_TAG'][1].replace('00', '')
                class_name = binascii.a2b_hex(class_name)

                # Get MSG type
                msg_type = int(flow_set['MSG_TYPE'], 16)

                # Action
                if max_ver in self.ofp_ver:
                    # Add flows
                    if msg_type == 0:
                        action = None

                        # Get table flow Priority
                        priority = int(flow_set['CLASS_TAG'][2], 16)

                        # Get Idle & Hard Timeout
                        timeout = int(flow_set['TIMEOUT'], 16)

                        # Get conf.ini classes
                        self.meter_var(class_name)

                        # Enqueue if it queue number exists
                        if self.queue is not None:
                            action = [parser.OFPActionSetQueue(
                                int(self.queue))]

                        # Create instruction
                        if action is not None:
                            inst = [
                                parser.OFPInstructionGotoTable(1),
                                parser.OFPInstructionActions(
                                    ofproto.OFPIT_APPLY_ACTIONS,
                                    action)]
                        else:
                            inst = [parser.OFPInstructionGotoTable(1)]

                        # Add meter/flow on SDN Switch
                        if self.meter_id is not None:
                            self.priority = priority
                            self.timeout = timeout
                            self.inst = inst
                            self.create_meter(datapath=datapath,
                                              load=load)
                        else:
                            self.add_flow(datapath=datapath,
                                          timeout=timeout,
                                          priority=priority,
                                          instruction=inst,
                                          load=load)

                    # Delete IP Flow
                    elif msg_type == 1:
                        self.delete_flow(datapath=datapath,
                                         load=load)
                        self.logger.info(
                            "%s Flow deletion sent", self.time_now())

                    # Delete All IP Flows
                    elif msg_type == 2:
                        # Reset match
                        load = []
                        load.extend([('eth_type', 0x0800)])

                        # Send delete
                        self.delete_flow(datapath=datapath,
                                         load=load)
                        self.logger.info(
                            "%s All flow deletion sent", self.time_now())
                    else:
                        self.logger.info(
                            "%s MSG_TYPE did not match", self.time_now())

    def meter_var(self, class_name):
        """Sets up meter variables

        Parameters
        ----------
        class_name: str
            The FCN decoded class name

        """
        config = self.conf_class_check(class_name)
        if config['queue'] is not None:
            self.queue = config['queue']
        else:
            self.queue = None

        self._type = config['type']
        self.meter_id = config['meter_id']
        self.rate = config['rate']
        self.dscp_no = config['dscp_no']

    def receive_parsed_data(self, sock):
        """Accepts any TCP connections that connect to the socket and parses
        the payload

        Parameters
        ----------
        sock: object
            The location of the socket

        Returns
        -------
        decoded_msg: str
            The packet's payload containing the parameter sets
        msg_count: int
            The number of sets of in the decoded msg

        """
        buffer_size = 1024

        # Accept TCP connection from a host
        conn, address = sock.accept()

        # Receive the packet, parse the payload and close the connection
        while True:
            data = conn.recv(buffer_size)
            if not data:
                break
            decoded_msg, msg_count = self.parse_rap_packets(data)
            conn.close()
            self.logger.info("%s Flow received", self.time_now())
            return decoded_msg, msg_count

    def parse_rap_packets(self, bin_data):
        """Decode Templates and return their corresponding hex values

        Parameters
        ----------
        bin_data: byte str
            The incoming raw payload

        Returns
        -------
        decoded_sets: list of dicts
            List of decoded sets where each dict contains the values
            for the corresponding Template ID.
        msg_counter: int
              The number of sets of in the decoded msg

        Raises
        ------
        ValueError:
            If there is a problem in checking the next set ID.

        """
        # Reset the offset for each message
        self.offset = 0

        # Initialise variables
        template = []
        msg = {}
        decoded_sets = []
        msg_counter = 0

        # Static hex to int length
        uint32 = 4
        uint16 = 2
        uint8 = 1

        # Packet payload to hex string
        str_data = binascii.b2a_hex(bin_data)
        split_msg = [str_data[i:i + 2] for i in range(0, len(str_data), 2)]

        # Create the header
        class Header:
            """Class containing packet header information

            Attribute
            ---------
            ver: hex str
                The Version Number
            m_len: hex str
                The length of payload
            seq_no: hex str
                The Sequence number
            time: hex str
                The time at which the message was created
            set_id: hex str
                The ID determines the type set
            set_len: hex str
                The length of this set

            """
            # Make header, parsing through raw bin_data
            ver = join(msg=split_msg, offset=self.offset, hex_len=8),
            self.offset += header_offset_check('ver')
            m_len = join(msg=split_msg, offset=self.offset, hex_len=uint16),
            self.offset += header_offset_check('m_len')
            seq_no = join(msg=split_msg, offset=self.offset, hex_len=uint32),
            self.offset += header_offset_check('seq_no')
            time = join(msg=split_msg, offset=self.offset, hex_len=uint32),
            self.offset += header_offset_check('time')
            set_id = join(msg=split_msg, offset=self.offset, hex_len=uint16),
            self.offset += header_offset_check('set_id')
            set_len = join(msg=split_msg, offset=self.offset, hex_len=uint16),
            self.offset += header_offset_check('set_len')

        header_set_id = Header.set_id[0]
        header_set_len = int(Header.set_len[0], 16) - 10
        # Decode the template if ID is 1
        if header_set_id == '0001':
            template_len = header_set_len

            template.append('T_ID')
            self.offset += uint16
            template.append('T_FLAG')
            self.offset += uint16

            for i in range(4, template_len, 2):
                template_id = join(
                    msg=split_msg, offset=self.offset, hex_len=uint16)
                template_name = template_check(template_id)

                if template_name not in ['CLASS_NAME', 'ACT', 'ACT_PAR']:
                    template.append(template_name)
                    self.offset += uint16
                else:
                    template.append(template_name)
                    self.offset += uint16
                    template.append(
                        int(join(msg=split_msg,
                                 offset=self.offset,
                                 hex_len=uint16), 16))
                    self.offset += uint16

        # Get next set id
        set_id = int(
            join(
                msg=split_msg,
                offset=self.offset,
                hex_len=uint16),
            16)
        self.offset += uint16

        msg_set_len = int(
            join(
                msg=split_msg,
                offset=self.offset,
                hex_len=uint16),
            16)
        self.offset += uint16

        # Parse through parameter set using the template ID
        while True:
            if set_id == 256:
                for i, template_id in enumerate(template):
                    msg[template[i]] = self.rap_msg_decoder(template_id,
                                                            split_msg,
                                                            set_id,
                                                            msg_set_len)
                    if not template_id == 'CLASS_TAG':
                        self.offset += msg_check(template[i], template)
                    else:
                        class_len = int(msg['CLASS_TAG'][0], 16)
                        self.offset += uint8 * class_len
            decoded_sets.append(copy.deepcopy(msg))
            try:
                if int(join(msg=split_msg,
                            offset=self.offset,
                            hex_len=uint16), 16) == 256:
                    continue
                else:
                    break
            except ValueError:
                break
            finally:
                self.offset += uint32
                msg_counter += 1
        return decoded_sets, msg_counter

    def add_flow(self, datapath, timeout, priority, instruction, load):
        """Sends add flow messages to the SDN Switch

        Parameters
        ----------
        datapath:
            The datapath of the destination SDN Switch.
        timeout: int
            The hard and idle timeout for the created rule.
        priority: int
            The priority on rule table.
        instruction: instance of OFPInstruction
            The instruction to execute on match in the rule table
        load: list of str
            The 5-tuple used for matching

        """
        # Get datapath functions
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()

        # Create match from FCN/CN parameters
        setattr(match, '_fields2', load)

        # Serialise and Send flow
        try:
            mod = parser.OFPFlowMod(datapath=datapath,
                                    idle_timeout=timeout,
                                    hard_timeout=timeout,
                                    priority=priority,
                                    match=match,
                                    instructions=instruction,
                                    table_id=0)
            self.logger.info(
                "%s Sending Flow", self.time_now())
            datapath.send_msg(mod)
        except RuntimeError:
            self.logger.error(
                "%s Could not send flow to switch \'%d\'",
                self.time_now(), datapath.id)
        else:
            self.logger.info(
                "%s Flow Creation sent to switch \'%d\'",
                self.time_now(), datapath.id)

    def delete_flow(self, datapath, load):
        """Removes single/all flows from table not including the controller

        Parameters
        ----------
        datapath: object
            The datapath of the destination SDN Switch
        load: list
            The 5-tuple used for matching

        Raises
        ------
        RuntimeError:
            If serialising or creating the delete OFPFlowMod fails.

        """
        # Get datapath functions
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()

        # Create match from FCN/CN parameters
        setattr(match, '_fields2', load)

        # Serialise and send delete flow using the match
        try:
            mod = parser.OFPFlowMod(
                datapath=datapath,
                cookie=0,
                cookie_mask=0,
                table_id=0,
                command=ofproto.OFPFC_DELETE,
                idle_timeout=0,
                hard_timeout=0,
                priority=1,
                buffer_id=ofproto.OFPCML_NO_BUFFER,
                out_port=ofproto.OFPP_ANY,
                out_group=ofproto.OFPG_ANY,
                flags=0,
                match=match,
                instructions=[])
            self.logger.info(
                "%s Sending Flow", self.time_now())
            datapath.send_msg(mod)
        except RuntimeError:
            self.logger.error(
                "%s Could not send flow deletion to switch \'%d\'",
                self.time_now(),
                datapath.id)
        else:
            self.logger.info(
                "%s Flow deletion sent to switch \'%d\'",
                self.time_now(),
                datapath.id)

    def import_conf(self):
        """Import conf.ini class names

        Returns
        -------
        class_name: list
            The list of class names imported

        """
        # Initialise ini importer
        self.config = ConfigParser.ConfigParser()

        # Read the conf.ini data
        # try:
        #    print('Input location of configuration file:')
        #    self.config.read(input())
        # except (ValueError, SyntaxError):
        self.config.read('./conf.ini')
        #    self.logger.info("using: ./conf.ini")

        # Get class names imported
        class_name = self.config.sections()
        return class_name

    def get_class_properties(self, matching_class):
        """Gets the properties for the corresponding class

        Parameters
        ----------
        matching_class: str
            The class used for the incoming FCN message.

        Returns
        -------
        class_properties: dict
            The mapped dictionary containing the properties corresponding to
            matching_class.

        """
        # Initialise data
        class_properties = {}
        options = self.config.options(matching_class)

        # Create sectioned dictionary
        for option in options:
            try:
                class_properties[option] = self.config.get(matching_class,
                                                           option)
                if class_properties[option] == -1:
                    self.logger.debug('skip: %s', option)
            except ConfigParser.Error:
                self.logger.error("exception on %s!", option)
                class_properties[option] = None

        return class_properties

    def conf_class_check(self, class_in='default'):
        """Check incoming RAP messages against conf.ini and get the required
        configuration

        Parameters
        ----------
        class_in: str
            The name of the decoded class name from the incoming FCN/CN message

        Returns
        -------
            The config values to be used corresponding to the decoded
            class

        Raises
        ------
        RuntimeError:
            If there is an error in importing the class properties

        """

        # Check if class name exists, get config parameters
        if class_in in self.class_name:
            class_name = class_in
        # Get 'default' config parameters if no match
        else:
            class_name = "default"

        self.logger.info(
            "%s Class Name: %s", self.time_now(), class_name)

        try:
            csm = self.get_class_properties(class_name)
            queue = csm.get('queue')  # queue number
            _type = csm.get('type')
            meter_id = csm.get('meterid')
            rate = csm.get('rate')
            dscp_no = csm.get('dscp')

            return dict(queue=queue,
                        type=_type,
                        meter_id=meter_id,
                        rate=rate,
                        dscp_no=dscp_no)
        except Exception:
            self.logger.error("%s Error importing class configurations",
                              self.time_now())
            raise RuntimeError()

    def create_meter(self, datapath, load):
        """Create meter and SDN flow rules

        Parameters
        ----------
        datapath:
            The datapath of the destination SDN Switch
        load:
            The 5-tuple used for matching

        """
        # Get datapath functions
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Get meter values to be used
        meter_id = int(self.meter_id)
        type_ = self._type
        rate = int(self.rate)
        dscp_no = int(self.dscp_no)

        # Check OpenFlow version of the switch
        ofp_ver = version_check(datapath.ofproto.OFP_VERSION)

        # Send Meter mod message for compatible version switches
        if ofp_ver in ['OF13', 'OF14']:
            # Create DROP meter for meter type 'drop'
            if type_ == 'drop':
                bands = [parser.OFPMeterBandDrop(rate=rate,
                                                 burst_size=0)]
                self.logger.info("%s Sending MeterMod: Type = DROP",
                                 self.time_now())

            # Create DSCP meter for meter type 'dscp'
            elif type_ == 'dscp':
                bands = [parser.OFPMeterBandDscpRemark(rate=rate,
                                                       burst_size=0,
                                                       prec_level=dscp_no)]
                self.logger.info("%s Sending MeterMod: Type = DSCP",
                                 self.time_now())

            # Serialise meter mod/add command
            meter_mod = parser.OFPMeterMod(datapath=datapath,
                                           command=ofproto.OFPMC_ADD,
                                           flags=ofproto.OFPMF_KBPS,
                                           meter_mod=meter_id,
                                           bands=bands)
            # Send meter mod/add
            datapath.send_msg(meter_mod)
        # Send flow
        self.send_meter(datapath, load)

    def send_meter(self, datapath, load):
        """Add flows that use meters

        Parameters
        ----------
        datapath:
            The datapath of the destination SDN Switch
        load:
            The 5-tuple used for matching

        """
        # Get datapath functions
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        # Set flow rule values
        timeout = self.timeout
        priority = self.priority
        meter_id = self.meter_id

        # Set Enqueue
        action = [parser.OFPActionSetQueue(int(self.queue))]
        # Set Goto next table
        inst = [parser.OFPInstructionGotoTable(1),
                parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             action)]
        # Set Meter ID that will monitor this flow
        inst.insert(0, parser.OFPInstructionMeter(int(meter_id)))

        # Initialise serialisation of the flow mod packet
        self.logger.info("%s Sending Flow", self.time_now())
        self.add_flow(datapath=datapath,
                      timeout=timeout,
                      priority=priority,
                      instruction=inst,
                      load=load)

    def rap_msg_decoder(self, msg_name, split_msg, msg_id, msg_len):
        """Decodes the parameter set using template names

        Parameters
        ----------
        msg_name:
            The current template name
        split_msg: lst
            The RAP array in hex
        msg_id:
            The SET ID
        msg_len:
            The length of the following set corresponding to the SET ID

        Returns
        -------
        The decoded values/strings for the corresponding Template name

        """
        # Static hex to int length
        uint64 = 8
        uint32 = 4
        uint16 = 2
        uint8 = 1

        # Get class name length
        c_tag = 0
        if msg_name == 'CLASS_TAG':
            c_tag = int(split_msg[self.offset], 16)

        # Return decoded values corresponding to the template name
        return {
            'T_ID': msg_id,
            'T_FLAG': msg_len,
            'CLASS_NAME': join(msg=split_msg, offset=self.offset, hex_len=uint64),
            'MSG_TYPE': join(msg=split_msg, offset=self.offset, hex_len=uint8),
            'SRC_IPV4': join(msg=split_msg, offset=self.offset, hex_len=uint32),
            'DST_IPV4': join(msg=split_msg, offset=self.offset, hex_len=uint32),
            'SRC_PORT': join(msg=split_msg, offset=self.offset, hex_len=uint16),
            'DST_PORT': join(msg=split_msg, offset=self.offset, hex_len=uint16),
            'PROTO': join(msg=split_msg, offset=self.offset, hex_len=uint8),
            'PKT_COUNT': join(msg=split_msg, offset=self.offset, hex_len=uint32),
            'KBYTE_COUNT': join(msg=split_msg, offset=self.offset, hex_len=uint32),
            'CLASS_TAG': {0: join(msg=split_msg, offset=self.offset, hex_len=uint8),
                          1: join(msg=split_msg, offset=self.offset + 1,
                                  hex_len=c_tag - 2),
                          2: join(msg=split_msg, offset=self.offset + c_tag - 1,
                                  hex_len=1)},
            'TIME_TYPE': join(msg=split_msg, offset=self.offset, hex_len=uint8),
            'TIMEOUT': join(msg=split_msg, offset=self.offset, hex_len=uint16),
            'ACT': join(msg=split_msg, offset=self.offset, hex_len=uint64),
            'ACT_FLAG': join(msg=split_msg, offset=self.offset, hex_len=uint16),
            'ACT_PAR': join(msg=split_msg, offset=self.offset, hex_len=16),
        }.get(msg_name)

    @set_ev_cls(ofp_event.EventOFPErrorMsg, MAIN_DISPATCHER)
    def meter_error_handler(self, event):
        """Prints an error if meter already exists in an SDN switch

        """
        if event.msg.type == 12:
            self.logger.error("%s Meter already exists, "
                              "existing meter was used", self.time_now())

    @staticmethod
    def add_flow_miss(datapath, priority, table_id):
        """Sends the add flow miss to the controller and a goto next table rules
            to the SDN switch

        Parameters
        ----------
        datapath :
            The datapath connected to the controller
        priority : int
            The priority of the rule created in the SDN switch
        table_id : int
            Table ID where the rule is created

        """
        # Get datapath functions
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()

        # Create go to next table instruction
        inst_goto_next = [parser.OFPInstructionGotoTable(table_id + 1)]

        # Create send packet to controller on match miss action
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        # Create apply action instruction
        inst_apply_action = [parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS, actions)]

        # Package Flow modification add messages
        flow_miss_mod = parser.OFPFlowMod(datapath=datapath,
                                          priority=priority,
                                          match=match,
                                          instructions=inst_apply_action,
                                          table_id=0)
        next_table_mod = parser.OFPFlowMod(datapath=datapath,
                                           priority=priority + 1,
                                           match=match,
                                           instructions=inst_goto_next,
                                           table_id=0)
        # Send messages to SDN Switch
        datapath.send_msg(flow_miss_mod)
        datapath.send_msg(next_table_mod)

    @staticmethod
    def msg_converter(flow_set, max_ver):
        """Get the 5-tuple parameters and convert them from hex

        Parameters
        ----------
        flow_set: dict
            The dictionary contains the parsed action parameters for one set
        max_ver: str 'OFXX'
            Highest supported version of the switch

        Returns
        ------
        match_parameters: tuple up to len 5
            Contains the 5-tuple information for match use

        """
        match_parameters = []

        # Check if protocol is either TCP or UDP
        proto = proto_check(int(flow_set['PROTO'], 16))

        # Create TCP Source and Destination ports
        tcp_src = int(flow_set['SRC_PORT'], 16)
        tcp_dst = int(flow_set['DST_PORT'], 16)
        # Create UDP Source and Destination ports
        udp_src = int(flow_set['SRC_PORT'], 16)
        udp_dst = int(flow_set['DST_PORT'], 16)

        # Create IPv4 Source and Destination IPs
        ipv4_src = socket.inet_ntoa(
            struct.pack(">L", int(flow_set['SRC_IPV4'], 16)))
        ipv4_dst = socket.inet_ntoa(
            struct.pack(">L", int(flow_set['DST_IPV4'], 16)))

        if max_ver in ['OF13', 'OF14', 'OF15']:
            # Append Source of Destination IP if they exist
            eth_type = 0x0800
            match_parameters.extend([('eth_type', eth_type)])
            if ipv4_src != '0.0.0.0':
                ipv4_src = ipv4_to_int(ipv4_src)
                match_parameters.extend([('ipv4_src', ipv4_src)])
            if ipv4_dst != '0.0.0.0':
                ipv4_dst = ipv4_to_int(ipv4_dst)
                match_parameters.extend([('ipv4_dst', ipv4_dst)])

            # Append TCP, its Source and Destination Port if they exist
            if proto == 'tcp':
                ip_proto = (int(flow_set['PROTO'], 16))
                match_parameters.extend([('ip_proto', ip_proto)])
                # Match TCP src port
                if tcp_src != 0:
                    match_parameters.extend([('tcp_src', tcp_src)])
                # Match TCP dst port
                if tcp_dst != 0:
                    match_parameters.extend([('tcp_dst', tcp_dst)])

            # Append UDP, its Source and Destination Port if they exist
            elif proto == 'udp':
                ip_proto = int(flow_set['PROTO'], 16)
                match_parameters.extend([('ip_proto', ip_proto)])
                # Match UDP src port
                if udp_src != 0:
                    match_parameters.extend([('udp_src', udp_src)])
                # Match UDP dst port
                if udp_dst != 0:
                    match_parameters.extend([('udp_dst', udp_dst)])

            # If the protocol is neither TCP/UDP, parse protocol number
            elif int(flow_set['PROTO'], 16) != 0:
                ip_proto = int(flow_set['PROTO'], 16)
                match_parameters.extend([('ip_proto', ip_proto)])
        return match_parameters

    @staticmethod
    def time_now():
        """Gives the current Time

        Returns
        -------
        cur_time: str in format DD-MM-YYYY HH:MM:SS
            The current time in string

        """
        cur_time = str(datetime.now().strftime("%d-%m-%Y %H:%M:%S"))
        return cur_time
