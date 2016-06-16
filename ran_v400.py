"""RAN_v400"""
# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import binascii
import socket
import struct
import copy
try:
    import configparser as ConfigParser
except ImportError:
    import ConfigParser
from datetime import datetime
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_4
from ryu.ofproto import ofproto_v1_5

from diffuse_parse import ipv4_to_int
from diffuse_parse import proto_check
from packet_process import check_header_offset
from packet_process import join
from packet_process import msg_check
from packet_process import template_check
from ver_check import version_check


class RAN(app_manager.RyuApp):
    """Ryu Action Node v400"""
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION,
                    ofproto_v1_4.OFP_VERSION,
                    ofproto_v1_5.OFP_VERSION]
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
        self.ofp_ver = {}
        self.datapaths = {}
        self.offset = 0
        self.class_name = self.import_conf()
        self.diffuse_parser = hub.spawn(self.diffuse_parser)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, event):
        """Handles connection between RYU and SDN Switches"""
        msg = event.msg
        datapath = msg.datapath
        self.ofp_ver = version_check(datapath.ofproto.OFP_VERSION)
        self.logger.debug(
            '- Highest OF Version Supported on Switch ID:\'%s\': %s',
            datapath.id,
            self.ofp_ver)

        if datapath.id not in self.datapaths:
            self.datapaths[datapath.id] = datapath
        else:  # Update
            self.datapaths.update({datapath.id: datapath})

        table_id = 0  # RAN always in lowest table
        priority = 0  # Miss flows are the last to match

        if self.ofp_ver in ('OF15', 'OF14', 'OF13'):
            self.add_flow_miss(
                datapath=datapath,
                priority=priority,
                table_id=table_id)
        else:
            self.logger.debug('Error: %s Unsupported Version', self.ofp_ver)

        self.logger.debug('Datapath \'%s\'', self.datapaths)

    @staticmethod
    def add_flow_miss(datapath, priority, table_id):
        """Add controller flows miss (v13, v14, v15)"""
        # Table 0 Miss flows will continue on to Table 1 and any flows created by
        # the RAN will be on Table 0
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        inst = [
            parser.OFPInstructionGotoTable(
                table_id +
                1)]  # Go to next table
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst,
                                table_id=table_id)
        datapath.send_msg(mod)

    def diffuse_parser(self):
        """Parses FCN/CN RAP Protocol messages"""
        host = ''
        port = 5000

        sock = self.socket_tcp(host=host, port=port)

        self.logger.info("%s RAN initiated", self.time_now())

        while True:
            # Receive Messages
            received_msg, msg_count = self.socket_receive(sock=sock)
            try:
                self.parser(received_msg, msg_count)
            except RuntimeError:
                print("Error: New Switch was added, trying again")
                self.parser(received_msg, msg_count)

    def parser(self, received_msg, msg_count):
        """Action depending on Msg Type"""
        for d_n, datapath_key in enumerate(self.datapaths):
            for msg_no in range(0, msg_count + 1, 1):
                r_msg = received_msg[msg_no]

                # Import Most Recent Datapath of switch
                datapath = self.datapaths[datapath_key]
                ofproto = datapath.ofproto
                parser = datapath.ofproto_parser
                max_ver = version_check(datapath.ofproto.OFP_VERSION)

                load = self.msg_converter(r_msg=r_msg, max_ver=max_ver)

                # ClassName Conversion
                class_name = r_msg['CLASS_TAG'][1].replace('00', '')
                class_name = binascii.a2b_hex(class_name)
                if max_ver in ['OF13', 'OF14', 'OF15']:
                    # Send all except inc
                    # Add flow if MsgType=0
                    if int(r_msg['MSG_TYPE'], 16) == 0:
                        # Flow Priority
                        priority = int(r_msg['CLASS_TAG'][2], 16)

                        # Idle & Hard Timeout
                        timeout = int(r_msg['TIMEOUT'], 16)
                        action = None

                        # conf.ini values
                        config = self.conf_class_check(class_name)
                        if config['queue'] is not None:
                            self.queue = config['queue']
                        else:
                            self.queue = 0
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
                    elif int(r_msg['MSG_TYPE'], 16) == 1:
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
    def msg_converter(r_msg, max_ver):
        """Get Tuple and convert"""
        # Check if protocol is either TCP or UDP
        proto = proto_check(int(r_msg['PROTO'], 16))

        # Create TCP src and dst ports
        tcp_src = int(r_msg['SRC_PORT'], 16)
        tcp_dst = int(r_msg['DST_PORT'], 16)
        # Create UDP src and dst ports
        udp_src = int(r_msg['SRC_PORT'], 16)
        udp_dst = int(r_msg['DST_PORT'], 16)

        # Create IPv4 src and dst variable
        ipv4_src = socket.inet_ntoa(
            struct.pack(">L", int(r_msg['SRC_IPV4'], 16)))
        ipv4_dst = socket.inet_ntoa(
            struct.pack(">L", int(r_msg['DST_IPV4'], 16)))

        load = []

        if max_ver in ['OF13', 'OF14', 'OF15']:
            # Match Type - IP
            eth_type = 0x0800
            load.extend([('eth_type', eth_type)])
            if ipv4_src != '0.0.0.0':
                ipv4_src = ipv4_to_int(ipv4_src)
                load.extend([('ipv4_src', ipv4_src)])
            if ipv4_dst != '0.0.0.0':
                ipv4_dst = ipv4_to_int(ipv4_dst)
                load.extend([('ipv4_dst', ipv4_dst)])
            # Match TCP
            if proto == 'tcp':
                ip_proto = (int(r_msg['PROTO'], 16))
                load.extend([('ip_proto', ip_proto)])
                # Match TCP src port
                if tcp_src != 0:
                    load.extend([('tcp_src', tcp_src)])
                # Match TCP dst port
                if tcp_dst != 0:
                    load.extend([('tcp_dst', tcp_dst)])
            # Match UDP
            elif proto == 'udp':
                ip_proto = int(r_msg['PROTO'], 16)
                load.extend([('ip_proto', ip_proto)])
                # Match UDP src port
                if udp_src != 0:
                    load.extend([('udp_src', udp_src)])
                # Match UDP dst port
                if udp_dst != 0:
                    load.extend([('udp_dst', udp_dst)])
            else:
                ip_proto = int(r_msg['PROTO'], 16)
                load.extend([('ip_proto', ip_proto)])
        return load

    def socket_tcp(self, host, port):
        """Bind & Create Sockets"""
        _sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.logger.info('%s Socket created', self.time_now())

        try:
            _sock.bind((host, port))
        except socket.error:
            self.logger.debug('%s Binding error', self.time_now())
            self.logger.debug(
                '%s Socket in TIME-WAIT state, wait until socket is closed',
                self.time_now())
            exit(1)
        else:
            self.logger.info('%s Binding successful', self.time_now())

        try:
            _sock.listen(1)
        except socket.error:
            self.logger.debug(
                '%s Cannot listen on port %d', str(
                    datetime.now()), port)
        else:
            self.logger.info(
                '%s Socket now listening on port %d', str(
                    datetime.now()), port)

        return _sock

    def socket_receive(self, sock):
        """Receive Message"""
        buffer_size = 1024
        conn, addr = sock.accept()
        while True:
            data = conn.recv(buffer_size)
            if not data:
                break
            msg = self.packet_parse(data)
            conn.close()
            self.logger.info("%s Flow received", self.time_now())
            return msg

    def packet_parse(self, data):
        """Decode Message"""
        self.offset = 0
        template = []
        msg = {}
        message_check = True
        lst = []
        msg_counter = 0
        uint64 = 8
        uint32 = 4
        uint16 = 2
        uint8 = 1

        # Packet payload to hex string
        payload = binascii.b2a_hex(data)
        split_msg = [payload[i:i + 2] for i in range(0, len(payload), 2)]

        # Header data
        class Header:
            """Initialise header"""
            ver = join(msg=split_msg, offset=self.offset, hex=8),
            self.offset += check_header_offset('ver')
            m_len = join(msg=split_msg, offset=self.offset, hex=uint16),
            self.offset += check_header_offset('m_len')
            seq_no = join(msg=split_msg, offset=self.offset, hex=uint32),
            self.offset += check_header_offset('seq_no')
            time = join(msg=split_msg, offset=self.offset, hex=uint32),
            self.offset += check_header_offset('time')
            set_id = join(msg=split_msg, offset=self.offset, hex=uint16),
            self.offset += check_header_offset('set_id')
            set_len = join(msg=split_msg, offset=self.offset, hex=uint16),
            self.offset += check_header_offset('set_len')

        # Template Order
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
                # print(template)

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
        self.add_flow_meter_13(datapath, load)

    def add_flow_meter_13(self, datapath, load):
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
