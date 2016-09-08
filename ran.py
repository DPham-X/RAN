# Copyright (c) 2016, Centre for Advanced Internet Architectures,
# Swinburne University of Technology. All rights reserved.
#
# Author: Dzuy Pham (dhpham@swin.edu.au)
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#
# The views and conclusions contained in the software and documentation are
# those of the authors and should not be interpreted as representing official
# policies, either expressed or implied, of the FreeBSD Project.
"""Ryu Action Node v1.01 - RYU based application

Usage
-----
ryu-manager ./ran.py

Information
-----------
- Compatible with ryu.app.simple_switch and ryu.app.rest_router running on Open
    vSwitch OpenFlow Table 1
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
import copy
import socket
import struct

# Import RYU required libraries
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from ryu.ofproto import ofproto_v1_0
from ryu.ofproto import ofproto_v1_2
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_4
from ryu.ofproto import ofproto_v1_5

# Import RAN required libraries
from lib.packet_process import ipv4_to_int
from lib.packet_process import proto_check
from lib.packet_process import header_offset_check
from lib.packet_process import join
from lib.packet_process import msg_check
from lib.packet_process import template_check
from lib.packet_process import time_now
from lib.packet_process import version_check


class RAN(app_manager.RyuApp):
    """Ryu Action Node Northbound Application

        - Parses 'Classifier Node' and 'Fake Classifier Node' based packets
        using the 'Remote Actions Protocol' (RAP).
        - Implements class based prioritisation set by a configuration file

    """
    # Supported OpenFlow Versions
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION,
                    ofproto_v1_2.OFP_VERSION,
                    ofproto_v1_3.OFP_VERSION,
                    ofproto_v1_4.OFP_VERSION,
                    ofproto_v1_5.OFP_VERSION]

    # Configuration Settings Store here
    config = None

    def __init__(self, *args, **kwargs):
        super(RAN, self).__init__(*args, **kwargs)

        # The supported RAN OpenFlow versions
        self.ofp_ver = ['OF13', 'OF14', 'OF15']

        # Contains the datapaths for each connected SDN switch
        self.datapaths = {}

        # Holds Template List
        self.template = []

        # Offset used to know location when parsing a RAP message.
        self.offset = 0

        # List of valid class names that have a configuration set, including a
        # required 'default' class
        self.port = 5000
        self.host = ''
        self.table_id = 0
        self.protocol = 'TCP'
        self.class_name = self.import_config()

        # Initialises the Diffuse Parser module to receive any RAP messages.
        hub.spawn(self.parser_initialiser)

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

        priority = 0  # Miss flows are the last to match

        # Create on flow-miss go to controller for compatible OpenFlow versions
        if ofp_ver in self.ofp_ver:
            self.add_flow_miss(datapath=datapath,
                               priority=priority,
                               table_id=self.table_id)
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
        if self.protocol == 'TCP':
            sock = self.listen_tcp_socket()
        elif self.protocol == 'UDP':
            exit('UDP Unsupported')
            # TODO: Placeholder for UDP socket
            sock = self.listen_udp_socket()

        self.logger.info("%s RAN initiated", time_now())
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
        host = self.host  # Listen on localhost
        port = self.port  # Listen on port 5000

        # Create socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.logger.info('%s Socket created', time_now())

        # Connect to socket
        try:
            sock.bind((host, port))
        except socket.error:
            self.logger.error('%s Binding error', time_now())
            self.logger.error(
                '%s Socket in TIME-WAIT state, wait until socket is closed',
                time_now())
            exit(1)
        else:
            self.logger.info('%s Binding successful', time_now())

        # Listen to the socket
        try:
            sock.listen(1)
        except socket.error:
            self.logger.error(
                '%s Cannot listen on port %d', time_now(), port)
        else:
            self.logger.info(
                '%s Socket now listening on port %d', time_now(), port)
        return sock

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
        buffer_size = 64000

        # Accept TCP connection from a host
        conn, __ = sock.accept()
        data = []
        # Receive the packet, parse the payload and close the connection
        while True:
            # Get from buffer
            received_data = conn.recv(buffer_size)
            # Add received data to total message
            data.append(received_data)
            # If buffer is empty then stop
            if not received_data:
                break
        conn.close()

        if data is not None:
            # Collapse received data into long byte string
            data = ''.join(data)
            self.logger.info("%s Flow received", time_now())
            try:
                # Parse RAP packet
                decoded_msg, msg_count = self.parse_rap_packets(data)
                return decoded_msg, msg_count
            except (ValueError, TypeError):
                self.logger.error("%s Error Parsing", time_now())

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
            information elements
        msg_count: int
            The number of sets of in the decoded msg

        """
        for __, datapath_key in enumerate(self.datapaths):
            # Import most recent 'Datapath' of switch and their functions
            datapath = self.datapaths[datapath_key]
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser

            # Check if the switch's datapath is compatible
            max_ver = version_check(datapath.ofproto.OFP_VERSION)

            for msg_index in range(0, msg_count, 1):

                if max_ver in self.ofp_ver:
                    # Get current set of information elements from the received
                    # message
                    flow_set = parameter_sets[msg_index]

                    load = self.msg_converter(flow_set=flow_set,
                                              max_ver=max_ver)

                    # ClassName Conversion
                    class_name = self.class_name_conversion(flow_set)

                    # Get MSG type
                    msg_type = int(flow_set['MSG_TYPE'], 16)

                    # Add flows
                    if msg_type == 0:
                        action = None

                        # Get table flow Priority
                        priority = int(flow_set['CLASS_TAG'][2], 16)

                        # Get Idle & Hard Timeout
                        timeout = int(flow_set['TIMEOUT'], 16)

                        # Get conf.ini classes
                        meter_config = self.config_class_check(class_name)

                        # Enqueue if queue number exists
                        if meter_config['queue'] is not None:
                            action = [parser.OFPActionSetQueue(
                                int(meter_config['queue']))]

                        # Add meter/flow on SDN Switch
                        if meter_config['meter_id'] is not None:
                            self.create_meter(datapath=datapath,
                                              meter_config=meter_config)
                            # Send flow
                            self.add_flow_metered(datapath=datapath,
                                                  timeout=timeout,
                                                  priority=priority,
                                                  load=load,
                                                  meter_config=meter_config)
                        else:
                            # Create instruction
                            if action is not None:
                                inst = [
                                    parser.OFPInstructionGotoTable(1),
                                    parser.OFPInstructionActions(
                                        ofproto.OFPIT_WRITE_ACTIONS,
                                        action)]
                            else:
                                inst = [parser.OFPInstructionGotoTable(1)]

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
                            "%s Flow deletion sent", time_now())

                    # Delete All IP Flows
                    elif msg_type == 2:
                        # Reset match
                        load = []
                        load.extend([('eth_type', 0x0800)])

                        # Send delete
                        self.delete_flow(datapath=datapath,
                                         load=load)
                        self.logger.info(
                            "%s All flow deletion sent", time_now())
                    else:
                        self.logger.info(
                            "%s MSG_TYPE did not match", time_now())

    @staticmethod
    def class_name_conversion(flow_set):
        """Cleans and converts the class name from hex from the flow set

        Parameters
        ----------
        flow_set: dict
            The current dictionary containing a set of information elements

        Returns
        -------
        class_name: string
            The ASCII name of the class
        """
        class_name_clean = flow_set['CLASS_TAG'][1].replace('00', '')
        class_name = binascii.a2b_hex(class_name_clean)

        return class_name

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
        msg = {}
        decoded_sets = []
        msg_counter = 0
        template = self.template

        # Static hex to int length
        uint32 = 4
        uint16 = 2
        uint8 = 1

        # Packet payload to hex string
        str_data = binascii.b2a_hex(bin_data)
        split_msg = [str_data[i:i + 2] for i in range(0, len(str_data), 2)]

        # Create the header
        class Header_(object):
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

            Returns
            -------
            self.offset:
                increases offset after parsing through header
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

        # Get next SET ID and Length
        header_set_id = Header_.set_id[0]
        header_set_len = int(Header_.set_len[0], 16) - 10

        # Decode the template if ID is 1
        if header_set_id == '0001':
            # Clean template
            template = []
            template_len = header_set_len

            template.append('T_ID')
            self.offset += uint16
            template.append('T_FLAG')
            self.offset += uint16

            # Append Template ID to ordered list
            for i in range(4, template_len, 2):
                template_id = join(
                    msg=split_msg, offset=self.offset, hex_len=uint16)
                template_name = template_check(template_id)

                if template_name not in ['CLASS_NAME', 'ACT', 'ACT_PAR']:
                    template.append(template_name)
                    self.offset += uint16
                # Special Case for CLASS_NAME, ACT, ACT_PAR
                # Append associated variables
                else:
                    template.append(template_name)
                    self.offset += uint16
                    template.append(
                        int(join(msg=split_msg,
                                 offset=self.offset,
                                 hex_len=uint16), 16))
                    self.offset += uint16

            # Get next SET ID and SET length
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

        # SET ID and length if no template
        else:
            set_id = int(header_set_id, 16)
            msg_set_len = header_set_len

        # Parse through parameter set using previous Template ID
        if not template == []:
            while True:
                if set_id == 256:
                    for i, template_id in enumerate(template):
                        # Associate Parameter set with Template ID
                        msg[template[i]] = self.rap_msg_decoder(template_id,
                                                                split_msg,
                                                                set_id,
                                                                msg_set_len)
                        if not template_id == 'CLASS_TAG':
                            self.offset += msg_check(template[i], template)
                        else:
                            class_len = int(msg['CLASS_TAG'][0], 16)
                            self.offset += uint8 * class_len
                # Store parsed parameters
                decoded_sets.append(copy.deepcopy(msg))
                # End parse when next SET ID isn't 256
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
            # Store Template
            self.template = template
            return decoded_sets, msg_counter
        else:
            self.logger.error("%s No Template found, flow ignored", time_now())
            decoded_sets = 0
            msg_counter = 0
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
                                    table_id=self.table_id)
            self.logger.info(
                "%s Sending Flow", time_now())
            datapath.send_msg(mod)
        except RuntimeError:
            self.logger.error(
                "%s Could not send flow to switch \'%d\'",
                time_now(), datapath.id)
        else:
            self.logger.info(
                "%s Flow Creation sent to switch \'%d\'",
                time_now(), datapath.id)

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
                table_id=self.table_id,
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
                "%s Sending Flow", time_now())
            datapath.send_msg(mod)
        except RuntimeError:
            self.logger.error(
                "%s Could not send flow deletion to switch \'%d\'",
                time_now(),
                datapath.id)
        else:
            self.logger.info(
                "%s Flow deletion sent to switch \'%d\'",
                time_now(),
                datapath.id)

    def import_config(self):
        """Import conf.ini class names

        Returns
        -------
        class_name: list
            The list of class names imported
        self.host: string
            The host for socket
        self.port: int
            The port for socket to listen on
        self.table_id: int
            The table ID to instantiate RAN flow rules

        """
        # Initialise ini importer
        self.config = ConfigParser.ConfigParser()

        # Read the conf.ini data
        self.config.read('./conf.ini')

        # Get imported class names
        class_name = self.config.sections()

        if 'SETTINGS' in class_name:
            properties = self.get_class_properties('SETTINGS')
            class_name.remove('SETTINGS')
            try:
                self.host = properties['host']
            except KeyError:
                self.logger.error(
                    "%s Could not get host config using default \'\'",
                    time_now())
            try:
                self.port = int(properties['port'])
            except (ValueError, KeyError):
                self.logger.error(
                    "%s Could not get port config using default \'5000\'",
                    time_now())
            try:
                self.table_id = int(properties['table_id'])
            except (ValueError, KeyError):
                self.logger.error(
                    "%s Could not get Table ID config using default \'0\'",
                    time_now())
            try:
                self.protocol = properties['protocol']
            except (ValueError, KeyError):
                self.logger.error(
                    "%s Could not get Protocol config using default \'TCP\'",
                    time_now())
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

    def config_class_check(self, class_in='default'):
        """Check incoming RAP messages against conf.ini and get the required
        configuration

        Parameters
        ----------
        class_in: str
            The name of the decoded class name from the incoming FCN/CN message

        Returns
        -------
            The imported conf.ini file values to be used corresponding to the
            decoded class

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
            "%s Class Name: %s", time_now(), class_name)

        try:
            csm = self.get_class_properties(class_name)
            queue = csm.get('queue')  # queue number
            type_ = csm.get('type')
            meter_id = csm.get('meterid')
            rate = csm.get('rate')
            dscp_no = csm.get('dscp')

            return dict(queue=queue,
                        type=type_,
                        meter_id=meter_id,
                        rate=rate,
                        dscp_no=dscp_no)
        except Exception:
            self.logger.error("%s Error importing class configurations",
                              time_now())
            raise RuntimeError()

    def create_meter(self, datapath, meter_config):
        """Create meter and SDN flow rules

        Parameters
        ----------
        datapath:
            The datapath of the destination SDN Switch
        meter_config: dict
            The settings to create meters

        """
        # Get datapath functions
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Get meter values to be used
        if meter_config['meter_id'] is not None:
            meter_id = int(meter_config['meter_id'])
        if meter_config['type'] is not None:
            meter_type = meter_config['type']
        if meter_config['rate'] is not None:
            rate = int(meter_config['rate'])
        if meter_config['dscp_no'] is not None:
            dscp_no = int(meter_config['dscp_no'])

        # Check OpenFlow version of the switch
        ofp_ver = version_check(datapath.ofproto.OFP_VERSION)

        # Send Meter mod message for compatible version switches
        if ofp_ver in ['OF13', 'OF14']:
            # Create DROP meter for meter type 'drop'
            if meter_type == 'drop':
                bands = [parser.OFPMeterBandDrop(rate=rate,
                                                 burst_size=0)]
                self.logger.info("%s Sending MeterMod: Type = DROP",
                                 time_now())

            # Create DSCP meter for meter type 'dscp'
            elif meter_type == 'dscp':
                bands = [parser.OFPMeterBandDscpRemark(rate=rate,
                                                       burst_size=0,
                                                       prec_level=dscp_no)]
                self.logger.info("%s Sending MeterMod: Type = DSCP",
                                 time_now())

            else:
                bands = []
            # Serialise meter mod/add command
            meter_mod = parser.OFPMeterMod(datapath=datapath,
                                           command=ofproto.OFPMC_ADD,
                                           flags=ofproto.OFPMF_KBPS,
                                           meter_id=meter_id,
                                           bands=bands)
            # Send meter mod to SDN switch
            datapath.send_msg(meter_mod)

    def add_flow_metered(
            self,
            datapath,
            timeout,
            priority,
            load,
            meter_config):
        """Add flows that use meters

        Parameters
        ----------
        datapath:
            The datapath of the destination SDN Switch
        timeout: int
            The time the SDN flow rule is in effect
        priority: int
            The position on the flow table
        load: list
            The 5-tuple used for matching
        meter_config: dict
            The settings to create meters

        """
        # Get datapath functions
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        # Set flow rule values
        meter_id = meter_config['meter_id']

        # Set Enqueue
        action = [parser.OFPActionSetQueue(int(meter_config['queue']))]
        # Set Goto next table
        inst = [parser.OFPInstructionGotoTable(1),
                parser.OFPInstructionActions(ofproto.OFPIT_WRITE_ACTIONS,
                                             action)]
        # Set Meter ID that will monitor this flow
        inst.insert(0, parser.OFPInstructionMeter(int(meter_id)))

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
        split_msg: list
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
                          1: join(msg=split_msg, offset=self.offset + 1, hex_len=c_tag - 2),
                          2: join(msg=split_msg, offset=self.offset + c_tag - 1, hex_len=1)},
            'TIME_TYPE': join(msg=split_msg, offset=self.offset, hex_len=uint8),
            'TIMEOUT': join(msg=split_msg, offset=self.offset, hex_len=uint16),
            'ACT': join(msg=split_msg, offset=self.offset, hex_len=uint64),
            'ACT_FLAG': join(msg=split_msg, offset=self.offset, hex_len=uint16),
            'ACT_PAR': join(msg=split_msg, offset=self.offset, hex_len=16),
        }.get(msg_name)

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
            ofproto.OFPIT_WRITE_ACTIONS, actions)]

        # Package Flow modification add messages
        flow_miss_mod = parser.OFPFlowMod(datapath=datapath,
                                          priority=priority,
                                          match=match,
                                          instructions=inst_apply_action,
                                          table_id=table_id)
        next_table_mod = parser.OFPFlowMod(datapath=datapath,
                                           priority=priority + 1,
                                           match=match,
                                           instructions=inst_goto_next,
                                           table_id=table_id)

        # Send messages to SDN Switch
        datapath.send_msg(flow_miss_mod)
        datapath.send_msg(next_table_mod)

    @staticmethod
    def msg_converter(flow_set, max_ver):
        """Extract the 5-tuple parameters and convert them from hex

        Parameters
        ----------
        flow_set: dict
            The dictionary contains the parsed information elements
            for one set
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
