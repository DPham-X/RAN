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
import time
try:
    import configparser as ConfigParser
except ImportError:
    import ConfigParser
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_4
from ryu.ofproto import ofproto_v1_5
from datetime import datetime
from src.diffuse_parse import ipv4_to_int
from src.diffuse_parse import proto_check
from src.packet_process import check_header_offset
from src.packet_process import join
from src.packet_process import msg_check
from src.packet_process import template_check
from src.ver_check import version_check


class RAN(app_manager.RyuApp):
    """Ryu Action Node v400"""
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION,
                    ofproto_v1_4.OFP_VERSION,
                    ofproto_v1_5.OFP_VERSION]
    meters = []
    meter_id = None
    MeterModType = 0

    def __init__(self, *args, **kwargs):
        super(RAN, self).__init__(*args, **kwargs)

        self.max_ver = {}
        self.datapaths = {}
        self.offset = 0
        self.class_name = self.import_conf()
        self.diffuse_parser = hub.spawn(self.diffuse_parser)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Handles connection between RYU and SDN Switches"""
        msg = ev.msg
        datapath = msg.datapath
        # self.ver = version_check(max(datapath.supported_ofp_version))
        self.max_ver = version_check(datapath.ofproto.OFP_VERSION)
        self.logger.debug(
            '- Highest OF Version Supported on Switch ID:\'%s\': %s',
            datapath.id,
            self.max_ver)

        if datapath.id not in self.datapaths:
            self.datapaths[datapath.id] = datapath
        else:  # Update
            self.datapaths.update({datapath.id: datapath})

        table_id = 0  # RAN always in lowest table
        priority = 0  # Miss flows are the last to match

        if self.max_ver in ('OF15', 'OF14', 'OF13'):
            self.add_flow_miss(
                datapath=datapath,
                priority=priority,
                table_id=table_id)
        else:
            self.logger.debug('Error: Unsupported Version')

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

        s = self.socket_tcp(host=host, port=port)

        while True:
            # Receive Messages
            received_msg, msg_count = self.socket_receive(sock=s)
            self.logger.debug("%s Flow received", str(datetime.now()))
            for d_n, datapath_key in enumerate(self.datapaths):
                for msg_no in range(0, msg_count + 1, 1):
                    r_msg = received_msg[msg_no]

                    # Check if protocol is either TCP or UDP
                    proto = proto_check(int(r_msg['PROTO'], 16))

                    # Create TCP src and dst ports
                    if proto == 'tcp':
                        tcp_src = int(r_msg['SRC_PORT'], 16)
                        tcp_dst = int(r_msg['DST_PORT'], 16)
                    # Create UDP src and dst ports
                    elif proto == 'udp':
                        udp_src = int(r_msg['SRC_PORT'], 16)
                        udp_dst = int(r_msg['DST_PORT'], 16)

                    # Create IPv4 src and dst variable
                    ipv4_src = socket.inet_ntoa(
                        struct.pack(">L", int(r_msg['SRC_IPV4'], 16)))
                    ipv4_dst = socket.inet_ntoa(
                        struct.pack(">L", int(r_msg['DST_IPV4'], 16)))

                    # Import Most Recent Datapath of switch
                    datapath = self.datapaths[datapath_key]
                    ofproto = datapath.ofproto
                    parser = datapath.ofproto_parser
                    max_ver = version_check(datapath.ofproto.OFP_VERSION)
                    # Match
                    match = parser.OFPMatch()
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
                        self.load = load
                        setattr(match, '_fields2', load)

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
                            config = self.conf_get(class_name)

                            self.queue = config.queue
                            self.type = config.type_
                            self.meter_id = config.meter_id
                            self.rate = config.rate
                            self.dscp_no = config.dscp_no

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
                                self.match = match
                                self.priority = priority
                                self.timeout = timeout
                                self.inst = inst
                                self.meter_req(datapath)
                                time.sleep(1)
                            else:
                                self.logger.debug(
                                    "%s Sending Flow", str(
                                        datetime.now()))
                                self.create_flow(
                                    datapath, timeout,
                                    priority, match, inst)

                        # Delete IP Flow if Msg Type=1
                        elif int(r_msg['MSG_TYPE'], 16) == 1:
                            self.logger.debug(
                                "%s Sending Flow", str(
                                    datetime.now()))
                            self.del_flow(datapath, match)
                            self.logger.debug(
                                "%s Flow deletion sent", str(
                                    datetime.now()))

                        # Delete All IP Flow if Msg Type=2
                        else:
                            # Match
                            match = parser.OFPMatch()
                            load = []
                            load.extend([('eth_type', 0x0800)])
                            setattr(match, '_fields2', load)
                            self.logger.debug(
                                "%s Sending Flow", str(
                                    datetime.now()))
                            self.del_flow(datapath, match)
                            self.logger.debug(
                                "%s All flow deletion sent", str(
                                    datetime.now()))

    def socket_tcp(self, host, port):
        """Bind & Create Sockets"""
        _sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.logger.debug('%s Socket created', str(datetime.now()))

        try:
            _sock.bind((host, port))
        except socket.error:
            self.logger.debug('%s Binding error', str(datetime.now()))
            self.logger.debug(
                '%s Socket in TIME-WAIT state, wait until socket is closed', str(datetime.now()))
            exit(1)
        else:
            self.logger.debug('%s Binding successful', str(datetime.now()))

        try:
            _sock.listen(1)
        except socket.error:
            self.logger.debug(
                '%s Cannot listen on port %d', str(
                    datetime.now()), port)
        else:
            self.logger.debug(
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
            return msg

    def packet_parse(self, data):
        """Decode Message"""
        self.offset = 0
        template = []
        msg = {}
        _MSG_ID_CHECK = True
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

        while _MSG_ID_CHECK:
            if msg_id == 256:
                for i, ID in enumerate(template):
                    msg[template[i]] = msg_parser(ID)
                    # print msg
                    if not ID == 'CLASS_TAG':
                        self.offset += msg_check(template[i], template)
                    else:
                        class_len = int(msg['CLASS_TAG'][0], 16)
                        self.offset += uint8 * class_len
            m = copy.deepcopy(msg)
            lst.append(m)
            try:
                if int(
                        join(
                            msg=split_msg,
                            offset=self.offset,
                            hex=uint16),
                        16) == 256:
                    _MSG_ID_CHECK = True
                else:
                    _MSG_ID_CHECK = False
            except ValueError:
                break
            else:
                self.offset += uint32
                msg_counter += 1
        return lst, msg_counter

    def create_flow(self, datapath, timeout, priority, match, inst):
        """Add FCN/CN Flows in table"""
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        setattr(match, '_fields2', self.load)
        print(match)
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
                "%s Could not send flow to switch \'%d\'", str(
                    datetime.now()), datapath.id)
        else:
            self.logger.debug(
                "%s Flow Creation sent to switch \'%d\'", str(
                    datetime.now()), datapath.id)


# Delete flow

    # Delete Flow
    def del_flow(self, datapath, match):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
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
                "%s Could not send flow deletion to switch \'%d\'", str(
                    datetime.now()), datapath.id)
        else:
            self.logger.debug(
                "%s Flow deletion sent to switch \'%d\'", str(
                    datetime.now()), datapath.id)

# Section off conf file
    def import_conf(self):
        """Read conf.ini"""
        self.config = ConfigParser.ConfigParser()
        print('Input location of configuration file:')

        try:
            self.config.read(input())
        except (ValueError, SyntaxError):
            self.config.read('/home/sdn/RAN/conf.ini')

        # self.config.read = conf_dir
        # if self.config.read == None:
        #    self.config.read('/home/ryu/conf.ini')
        # self.config.read('/home/sdn/RAN/conf.ini')
        class_name = self.config.sections()
        return class_name

    # Section out conf.ini
    def config_section_map(self, section):
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

    # Parser for conf.ini
    def conf_get(self, class_in):
        if class_in in self.class_name:
            csm = self.config_section_map(class_in)
            queue = csm.get('queue')  # queue number
            type_ = csm.get('type')
            meter_id = csm.get('meterid')
            rate = csm.get('rate')
            dscp_no = csm.get('dscp')
        else:
            csm = self.config_section_map('default')
            queue = csm.get('queue')  # queue number
            type_ = csm.get('type')
            meter_id = csm.get('meterid')
            rate = csm.get('rate')
            dscp_no = csm.get('dscp')

        config = ()

        return config(queue=queue,
                      type=type_,
                      meter_id=meter_id,
                      rate=rate,
                      dscp_no=dscp_no)

    def meter_req(self, datapath):
        """Query Meter Stats Request when Packet Decoder has compeleted."""
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        req = parser.OFPMeterStatsRequest(datapath=datapath,
                                          flags=0,
                                          meter_id=ofproto.OFPM_ALL)
        datapath.send_msg(req)
        self.logger.debug(
            "%s MeterStatsRequest sent to switch \'%s\', waiting for reply...", str(
                datetime.now()), datapath.id)

    @set_ev_cls(ofp_event.EventOFPMeterStatsReply, MAIN_DISPATCHER)
    def meter_stats_reply_handler(self, ev):
        """Decode meters stats replies"""
        # TODO: Meter for OF1.5
        # Potential problem: Variables stored waiting for the meter stats reply
        # If new meter mod comes then old meter variables will be deleted before
        # it is send by the reply handler.
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.logger.debug(
            "%s MeterStatsReply received for switch \'%s\'", str(
                datetime.now()), datapath.id)

        meter_id = self.meter_id
        type_ = self.type_
        rate = self.rate
        dscp_no = self.dscp_no
        meters = []
        # print(meter_id)
        ver = version_check(datapath.ofproto.OFP_VERSION)

        if ver in ['OF13', 'OF14']:
            for stat in ev.msg.body:
                meters.append(stat.meter_id)
            if self.meter_id is not None:
                if int(self.meter_id) not in meters:
                    if type_ == 'drop':
                        bands = [
                            parser.OFPMeterBandDrop(
                                rate=int(rate),
                                burst_size=0)]
                        meter_mod = parser.OFPMeterMod(
                            datapath, ofproto.OFPMC_ADD, ofproto.OFPMF_KBPS, int(meter_id), bands)
                        self.logger.debug(
                            "%s Sending MeterMod: Type = DROP", str(
                                datetime.now()))
                        datapath.send_msg(meter_mod)
                    elif type_ == 'dscp':
                        bands = [
                            parser.OFPMeterBandDscpRemark(
                                rate=int(rate),
                                burst_size=0,
                                prec_level=int(dscp_no))]
                        meter_mod = parser.OFPMeterMod(
                            datapath, ofproto.OFPMC_ADD, ofproto.OFPMF_KBPS, int(meter_id), bands)
                        self.logger.debug(
                            "%s Sending MeterMod: Type = DSCP", str(
                                datetime.now()))
                        datapath.send_msg(meter_mod)
                else:
                    self.logger.debug(
                        "%s Existing Meter ID detected, Old meter will be used", str(
                            datetime.now()))

            self.add_flow_meter_13(datapath)

    def add_flow_meter_13(self, datapath):
        """Add flow when meter exists"""
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        timeout = self.timeout
        priority = self.priority
        match = self.match
        meter_id = self.meter_id

        action = [parser.OFPActionSetQueue(int(self.queue))]
        inst = [
            parser.OFPInstructionGotoTable(1),
            parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS,
                action)]
        inst.insert(0, parser.OFPInstructionMeter(int(meter_id)))
        self.logger.debug("%s Sending Flow", str(datetime.now()))
        self.create_flow(
            datapath=datapath,
            timeout=timeout,
            priority=priority,
            match=match,
            inst=inst)
