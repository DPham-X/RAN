"""Ryu Action Node v2 - RYU based application

Run:
    ryu-manager ./ran_v2.py

- Compatible with ryu.app.simple_switch and ryu.app.rest_router running on Open vSwitch OpenFlow Table 2
- Supports Multi Version Switches
    - OpenFlow 1.3
    - OpenFlow 1.4
    - OpenFlow 1.5 (Limited, no meters)
- Supports Multiple Switches

"""

# Import common internal libraries
import binascii
import socket
import struct
import copy
import ConfigParser
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
from diffuse_parse import ipv4_to_int
from diffuse_parse import proto_check
from packet_process import header_offset_check
from packet_process import join
from packet_process import msg_check
from packet_process import template_check
from ver_check import version_check


class RAN(app_manager.RyuApp):
    """Ryu Action Node v2 Northbound Application
    - Parses 'Classifier Node' and 'Fake Classifier Node' based packets using the 'Remote Actions Protocol' (RAP).
    - Implements class based prioritisation set by a configuration file

    """
    # List of supported OpenFlow Versions
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION,
                    ofproto_v1_4.OFP_VERSION,
                    ofproto_v1_5.OFP_VERSION]
    # Initialise variables
    config = None
    dscp_no = 0
    inst = None
    meter_id = None
    meters = []
    priority = None
    queue = 0
    rate = 0
    type_ = 0
    timeout = None

    def __init__(self, *args, **kwargs):
        super(RAN, self).__init__(*args, **kwargs)

        # Contains the versions for each connected SDN switch
        self.ofp_ver = {}

        # Contains the datapaths for each connected SDN switch
        self.datapaths = {}

        # Offset used to know location when parsing a RAP message.
        self.offset = 0

        # List of valid class names that have a configuration set, including a
        # required 'default' class
        self.class_name = self.import_conf()

        # Initialises the Diffuse Parser module to receive any RAP messages.
        self.diffuse_parser_initialiser = hub.spawn(self.diffuse_parser_initialiser)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, event):
        """Handles connection between RYU and the SDN Switches
        If the version of the SDN Switch is supported, create a rule which sends all flow miss packets to the controller

        Parameters
        ----------
        event: ?
            The event of when a new switch connects to a controller

        """
        msg = event.msg
        datapath = msg.datapath
        # Get OpenFlow Version for connected switch
        self.ofp_ver = version_check(datapath.ofproto.OFP_VERSION)
        self.logger.debug(
            '- Highest OF Version Supported on Switch ID:\'%s\': %s',
            datapath.id,
            self.ofp_ver)

        # Add/Update Switch datapath into list of connected switches
        if datapath.id not in self.datapaths:
            self.datapaths[datapath.id] = datapath
        else:
            self.datapaths.update({datapath.id: datapath})

        table_id = 0  # RAN always in lowest table
        priority = 0  # Miss flows are the last to match

        # Create on flow-miss go to controller rule on SDN Switch if OpenFlow version is compatible
        if self.ofp_ver in ('OF15', 'OF14', 'OF13'):
            self.add_flow_miss(
                datapath=datapath,
                priority=priority,
                table_id=table_id)
        else:
            self.logger.debug('Error: %s Unsupported Version', self.ofp_ver)

        self.logger.debug('Datapath \'%s\'', self.datapaths)

    def add_flow_miss(self, datapath, priority, table_id):
        # TODO
        """Sends the add flow miss to the controller and a goto next table rules to the SDN switch

        Parameters
        ----------
        datapath : class?
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

        # Create first instruction - Go to next table
        inst_goto_next = [parser.OFPInstructionGotoTable(table_id + 1)]
        # Create action - Send packet to controller on match miss
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        # Create second instruction from action
        inst_apply_action = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        # Package Flow modification add messages
        mod1 = parser.OFPFlowMod(datapath=datapath,
                                 priority=priority,
                                 match=match,
                                 instructions=inst_apply_action,
                                 table_id=0)
        mod2 = parser.OFPFlowMod(datapath=datapath,
                                 priority=priority + 1,
                                 match=match,
                                 instructions=inst_goto_next,
                                 table_id=0)

        # Send messages to SDN Switch
        datapath.send_msg(mod1)
        datapath.send_msg(mod2)

    def diffuse_parser_initialiser(self):
        """Initialises the parser for Fake Classifier Node and Classifier Nodes' RAP Protocol messages

        """
        host = ''  # Listen on localhost
        port = 5000  # Listen on port 5000

        # Initialise the socket to listen on host and port using TCP
        sock = self.socket_tcp(host=host, port=port)
        self.logger.info("%s RAN initiated", self.time_now())

        while True:
            # Receive incoming messages
            received_msg, msg_count = self.socket_receive(sock=sock)

            # Parse and implement message through RYU
            try:
                self.parser_action(received_msg, msg_count)
            except RuntimeError:
                print("Error: New Switch was added, trying again")
                self.parser_action(received_msg, msg_count)

    def parser_action(self, received_msg, msg_count):
        """Implements parsed data depending on Msg Type

        MsgType : 0
            Send Add Flow to the SDN Switch
        MsgType : 1
            Delete matching 5-tuple IP Flows
        MsgType : 2
            Delete all IP Flows

        Parameters
        ----------
        received_msg: list
            Each index of the list contains a dictionary containing a set of Action Parameters
        msg_count: int
            Number of sets of Action parameters parsed

        """
        for d_n, datapath_key in enumerate(self.datapaths):
            for msg_index in range(0, msg_count + 1, 1):
                # Get current set of action parameters from the received message
                parameter_set = received_msg[msg_index]

                # Import most recent 'Datapath' of switch and their functions
                datapath = self.datapaths[datapath_key]
                ofproto = datapath.ofproto
                parser = datapath.ofproto_parser
                # Check if the switch's datapath is compatible
                max_ver = version_check(datapath.ofproto.OFP_VERSION)

                load = self.msg_converter(parameter_set=parameter_set, max_ver=max_ver)

                # ClassName Conversion
                class_name = parameter_set['CLASS_TAG'][1].replace('00', '')
                class_name = binascii.a2b_hex(class_name)
                if max_ver in ['OF13', 'OF14', 'OF15']:
                    # Send all except inc
                    # Add flow if MsgType=0
                    if int(parameter_set['MSG_TYPE'], 16) == 0:
                        # Flow Priority
                        priority = int(parameter_set['CLASS_TAG'][2], 16)

                        # Idle & Hard Timeout
                        timeout = int(parameter_set['TIMEOUT'], 16)
                        action = None

                        # conf.ini values
                        config = self.conf_class_check(class_name)
                        if config['queue'] is not None:
                            self.queue = config['queue']
                        else:
                            self.queue = None
                        self.type_ = config['type']
                        self.meter_id = config['meter_id']
                        self.rate = config['rate']
                        self.dscp_no = config['dscp_no']

                        if self.queue is not None:
                            action = [parser.OFPActionSetQueue(
                                int(self.queue))]

                        if action is not None:
                            inst = [
                                parser.OFPInstructionGotoTable(1),
                                parser.OFPInstructionActions(
                                    ofproto.OFPIT_APPLY_ACTIONS,
                                    action)]
                        else:
                            inst = [parser.OFPInstructionGotoTable(1)]

                        if self.meter_id is not None:
                            self.priority = priority
                            self.timeout = timeout
                            self.inst = inst
                            self.create_meter(datapath, load)
                        else:
                            self.logger.info(
                                "%s Sending Flow", self.time_now())
                            self.create_flow(
                                datapath, timeout,
                                priority, inst, load)

                    # Delete IP Flow if Msg Type=1
                    elif int(parameter_set['MSG_TYPE'], 16) == 1:
                        self.logger.info(
                            "%s Sending Flow", self.time_now())
                        self.delete_flow(datapath, load)
                        self.logger.info(
                            "%s Flow deletion sent", self.time_now())

                    # Delete All IP Flow if Msg Type=2
                    else:
                        # Match
                        load = []
                        load.extend([('eth_type', 0x0800)])
                        self.logger.info(
                            "%s Sending Flow", self.time_now())
                        self.delete_flow(datapath, load)
                        self.logger.info(
                            "%s All flow deletion sent", self.time_now())

    @staticmethod
    def msg_converter(parameter_set, max_ver):
        """Get the 5-tuple parameters and convert them from hex

        Parameters
        ----------
        parameter_set: dict
            The dictionary contains all the parsed action parameters for a set
        max_ver: str
            Highest supported version of the switch

        Return
        ------
        match_parameters: tuple up to len 5
            Contains the 5-tuple information for match use

        """
        match_parameters = []

        # Check if protocol is either TCP or UDP
        proto = proto_check(int(parameter_set['PROTO'], 16))

        # Create TCP Source and Destination ports
        tcp_src = int(parameter_set['SRC_PORT'], 16)
        tcp_dst = int(parameter_set['DST_PORT'], 16)
        # Create UDP Source and Destination ports
        udp_src = int(parameter_set['SRC_PORT'], 16)
        udp_dst = int(parameter_set['DST_PORT'], 16)

        # Create IPv4 Source and Destination IPs
        ipv4_src = socket.inet_ntoa(
            struct.pack(">L", int(parameter_set['SRC_IPV4'], 16)))
        ipv4_dst = socket.inet_ntoa(
            struct.pack(">L", int(parameter_set['DST_IPV4'], 16)))

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
                ip_proto = (int(parameter_set['PROTO'], 16))
                match_parameters.extend([('ip_proto', ip_proto)])
                # Match TCP src port
                if tcp_src != 0:
                    match_parameters.extend([('tcp_src', tcp_src)])
                # Match TCP dst port
                if tcp_dst != 0:
                    match_parameters.extend([('tcp_dst', tcp_dst)])

            # Append UDP, its Source and Destination Port if they exist
            elif proto == 'udp':
                ip_proto = int(parameter_set['PROTO'], 16)
                match_parameters.extend([('ip_proto', ip_proto)])
                # Match UDP src port
                if udp_src != 0:
                    match_parameters.extend([('udp_src', udp_src)])
                # Match UDP dst port
                if udp_dst != 0:
                    match_parameters.extend([('udp_dst', udp_dst)])

            # If the protocol is neither TCP/UDP parse number
            elif int(parameter_set['PROTO'], 16) is not 0:
                ip_proto = int(parameter_set['PROTO'], 16)
                match_parameters.extend([('ip_proto', ip_proto)])
        return match_parameters

    def socket_tcp(self, host, port):
        """Create Sockets and listen on that port

        Parameters
        ----------
        host: str
            The place to listen from
        port: int
            The port to listen from

        Returns
        -------
        sock:
            The location of the socket
        """

        # Create socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.logger.info('%s Socket created', self.time_now())

        # Bind to socket
        try:
            sock.bind((host, port))
        except socket.error:
            self.logger.debug('%s Binding error', self.time_now())
            self.logger.debug(
                '%s Socket in TIME-WAIT state, wait until socket is closed',
                self.time_now())
            exit(1)
        else:
            self.logger.info('%s Binding successful', self.time_now())

        # Listen to the socket
        try:
            sock.listen(1)
        except socket.error:
            self.logger.debug(
                '%s Cannot listen on port %d', str(
                    datetime.now()), port)
        else:
            self.logger.info(
                '%s Socket now listening on port %d', str(
                    datetime.now()), port)
        return sock

    def socket_receive(self, sock):
        """Accepts any TCP connections that connect to the socket and parses the payload

        Parameters
        ----------
        sock:
            The location of the socket

        Returns
        -------
        msg:
            The packet's payload containing the parameter sets
        msg_count:
            The number of parameter sets parsed in the message

        """
        buffer_size = 1024

        # Accept TCP connection from a host
        conn, address = sock.accept()

        # Receive the packet, parse the payload and close the connection
        while True:
            data = conn.recv(buffer_size)
            if not data:
                break
            msg, msg_count = self.packet_parse(data)
            conn.close()
            self.logger.info("%s Flow received", self.time_now())
            return msg, msg_count

    def packet_parse(self, data):
        """Decode Message

        Parameters
        ----------
        data:
            The incoming payload
        """
        # Reset the offset for each messages
        self.offset = 0

        # Initialise variables
        template = []
        msg = {}
        message_check = True
        lst = []
        msg_counter = 0

        # Static hex to int length
        uint64 = 8
        uint32 = 4
        uint16 = 2
        uint8 = 1

        # Packet payload to hex string
        payload = binascii.b2a_hex(data)
        split_msg = [payload[i:i + 2] for i in range(0, len(payload), 2)]

        # Create the header
        class Header:
            """Initialise header

            ver:
                The Version Number
            m_len:
                The length of payload
            seq_no:
                The Sequence number
            time:
                The time at which the message was created
            set_id:
                The ID determines the type set
            set_len:
                The length of this set

            """
            ver = join(msg=split_msg, offset=self.offset, hex=8),
            self.offset += header_offset_check('ver')
            m_len = join(msg=split_msg, offset=self.offset, hex=uint16),
            self.offset += header_offset_check('m_len')
            seq_no = join(msg=split_msg, offset=self.offset, hex=uint32),
            self.offset += header_offset_check('seq_no')
            time = join(msg=split_msg, offset=self.offset, hex=uint32),
            self.offset += header_offset_check('time')
            set_id = join(msg=split_msg, offset=self.offset, hex=uint16),
            self.offset += header_offset_check('set_id')
            set_len = join(msg=split_msg, offset=self.offset, hex=uint16),
            self.offset += header_offset_check('set_len')

        # Decode the template if ID is 1
        if Header.set_id[0] == '0001':
            template_len = int(''.join(Header.set_len[0]), 16) - 10

            template.append('T_ID')
            self.offset += uint16
            template.append('T_FLAG')
            self.offset += uint16
            for i in range(4, template_len, 2):
                template_id = join(
                    msg=split_msg, offset=self.offset, hex=uint16)
                template_name = template_check(template_id)

                if template_name not in ['CLASS_NAME', 'ACT', 'ACT_PAR']:
                    template.append(template_name)
                    self.offset += uint16
                else:
                    template.append(template_name)
                    self.offset += uint16
                    template.append(
                        int(join(msg=split_msg, offset=self.offset, hex=uint16), 16))
                    self.offset += uint16

        # MSG Parser
        msg_id = int(join(msg=split_msg, offset=self.offset, hex=uint16), 16)
        self.offset += uint16
        msg_len = int(join(msg=split_msg, offset=self.offset, hex=uint16), 16)
        self.offset += uint16

        def msg_parser(msg_name):
            """Packet Decoder"""
            c_tag = 0
            if msg_name == 'CLASS_TAG':
                c_tag = int(split_msg[self.offset], 16)
            return {
                'T_ID': msg_id,
                'T_FLAG': msg_len,
                'CLASS_NAME': join(msg=split_msg, offset=self.offset, hex=uint64),
                'MSG_TYPE': join(msg=split_msg, offset=self.offset, hex=uint8),
                'SRC_IPV4': join(msg=split_msg, offset=self.offset, hex=uint32),
                'DST_IPV4': join(msg=split_msg, offset=self.offset, hex=uint32),
                'SRC_PORT': join(msg=split_msg, offset=self.offset, hex=uint16),
                'DST_PORT': join(msg=split_msg, offset=self.offset, hex=uint16),
                'PROTO': join(msg=split_msg, offset=self.offset, hex=uint8),
                'PKT_COUNT': join(msg=split_msg, offset=self.offset, hex=uint32),
                'KBYTE_COUNT': join(msg=split_msg, offset=self.offset, hex=uint32),
                'CLASS_TAG': {0: join(msg=split_msg, offset=self.offset, hex=uint8),
                              1: join(msg=split_msg, offset=self.offset + 1, hex=c_tag - 2),
                              2: join(msg=split_msg, offset=self.offset + c_tag - 1, hex=1)},
                'TIME_TYPE': join(msg=split_msg, offset=self.offset, hex=uint8),
                'TIMEOUT': join(msg=split_msg, offset=self.offset, hex=uint16),
                'ACT': join(msg=split_msg, offset=self.offset, hex=uint64),
                'ACT_FLAG': join(msg=split_msg, offset=self.offset, hex=uint16),
                'ACT_PAR': join(msg=split_msg, offset=self.offset, hex=16),
            }.get(msg_name)

        while message_check:
            if msg_id == 256:
                for i, template_id in enumerate(template):
                    msg[template[i]] = msg_parser(template_id)
                    # print msg
                    if not template_id == 'CLASS_TAG':
                        self.offset += msg_check(template[i], template)
                    else:
                        class_len = int(msg['CLASS_TAG'][0], 16)
                        self.offset += uint8 * class_len
            new_msg = copy.deepcopy(msg)
            lst.append(new_msg)
            try:
                if int(
                        join(
                            msg=split_msg,
                            offset=self.offset,
                            hex=uint16),
                        16) == 256:
                    message_check = True
                else:
                    message_check = False
            except ValueError:
                break
            else:
                self.offset += uint32
                msg_counter += 1
        return lst, msg_counter

    def create_flow(self, datapath, timeout, priority, inst, load):
        """Add FCN/CN Flows in table"""
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        setattr(match, '_fields2', load)
        # for tuples in match._fields2:
        #     self.logger.debug("%s", tuples)
        try:
            mod = parser.OFPFlowMod(
                datapath=datapath,
                idle_timeout=timeout,
                hard_timeout=timeout,
                priority=priority,
                match=match,
                instructions=inst,
                table_id=0)
            datapath.send_msg(mod)
        except RuntimeError:
            self.logger.debug(
                "%s Could not send flow to switch \'%d\'",
                self.time_now(),
                datapath.id)
        else:
            self.logger.info(
                "%s Flow Creation sent to switch \'%d\'",
                self.time_now(),
                datapath.id)

    def delete_flow(self, datapath, load):
        """Removes single/all flows from table
        not including the controller"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        setattr(match, '_fields2', load)
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
            datapath.send_msg(mod)
        except RuntimeError:
            self.logger.debug(
                "%s Could not send flow deletion to switch \'%d\'",
                self.time_now(),
                datapath.id)
        else:
            self.logger.info(
                "%s Flow deletion sent to switch \'%d\'",
                self.time_now(),
                datapath.id)

# Section off conf file

    def import_conf(self):
        """Read conf.ini"""
        self.config = ConfigParser.ConfigParser()
        print('Input location of configuration file:')

        try:
            self.config.read(input())
        except (ValueError, SyntaxError):
            self.config.read('/home/sdn/RAN/conf.ini')
            self.logger.info("using: /home/sdn/RAN/conf.ini")

        # self.config.read = conf_dir
        # if self.config.read == None:
        #    self.config.read('/home/ryu/conf.ini')
        # self.config.read('/home/sdn/RAN/conf.ini')
        class_name = self.config.sections()
        return class_name

    def conf_section_map(self, section):
        """Split conf.ini into sections"""
        csm_d = {}
        options = self.config.options(section)
        for option in options:
            try:
                csm_d[option] = self.config.get(section, option)
                if csm_d[option] == -1:
                    self.logger.debug('skip: %s', option)
                    # DebugPrint("skip: %s" % option)
            except ConfigParser.Error:
                print("exception on %s!" % option)
                csm_d[option] = None
        return csm_d

    def conf_class_check(self, class_in):
        """Check incoming RAP messages against conf.ini"""
        if class_in in self.class_name:
            class_name = class_in
            csm = self.conf_section_map(class_in)
            queue = csm.get('queue')  # queue number
            type_ = csm.get('type')
            meter_id = csm.get('meterid')
            rate = csm.get('rate')
            dscp_no = csm.get('dscp')
        else:
            class_name = "default"
            csm = self.conf_section_map('default')
            queue = csm.get('queue')  # queue number
            type_ = csm.get('type')
            meter_id = csm.get('meterid')
            rate = csm.get('rate')
            dscp_no = csm.get('dscp')
        self.logger.info(
            "%s Class Name: %s", self.time_now(), class_name)

        return dict(queue=queue,
                    type=type_,
                    meter_id=meter_id,
                    rate=rate,
                    dscp_no=dscp_no)

    def create_meter(self, datapath, load):
        """Create meter."""
        # Get Var
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        meter_id = self.meter_id
        type_ = self.type_
        rate = self.rate
        dscp_no = self.dscp_no
        ofp_ver = version_check(datapath.ofproto.OFP_VERSION)
        meter_mod = None

        if ofp_ver in ['OF13', 'OF14']:
            # If DROP make drop
            if type_ == 'drop':
                bands = [
                    parser.OFPMeterBandDrop(
                        rate=int(rate),
                        burst_size=0)]
                meter_mod = parser.OFPMeterMod(
                    datapath,
                    ofproto.OFPMC_ADD,
                    ofproto.OFPMF_KBPS,
                    int(meter_id),
                    bands)
                self.logger.info(
                    "%s Sending MeterMod: Type = DROP", self.time_now())
            # if DSCP make DSCP
            elif type_ == 'dscp':
                bands = [
                    parser.OFPMeterBandDscpRemark(
                        rate=int(rate),
                        burst_size=0,
                        prec_level=int(dscp_no))]
                meter_mod = parser.OFPMeterMod(
                    datapath,
                    ofproto.OFPMC_ADD,
                    ofproto.OFPMF_KBPS,
                    int(meter_id),
                    bands)
                self.logger.info(
                    "%s Sending MeterMod: Type = DSCP", self.time_now())
            if meter_mod is not None:
                datapath.send_msg(meter_mod)
        # Send flow
        self.add_flow_meter(datapath, load)

    def add_flow_meter(self, datapath, load):
        """Add flow when meter exists"""
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        timeout = self.timeout
        priority = self.priority
        meter_id = self.meter_id
        action = [parser.OFPActionSetQueue(int(self.queue))]
        inst = [
            parser.OFPInstructionGotoTable(1),
            parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS,
                action)]
        inst.insert(0, parser.OFPInstructionMeter(int(meter_id)))
        self.logger.info("%s Sending Flow", self.time_now())
        self.create_flow(
            datapath=datapath,
            timeout=timeout,
            priority=priority,
            inst=inst,
            load=load)

    @set_ev_cls(ofp_event.EventOFPErrorMsg, MAIN_DISPATCHER)
    def meter_error_handler(self, event):
        """CLI Error Handler"""
        if event.msg.type == 12:
            self.logger.info("%s Meter already exists, "
                             "existing meter was used", self.time_now())

    @staticmethod
    def time_now():
        """Current Time"""
        cur_time = str(datetime.now())
        return cur_time
