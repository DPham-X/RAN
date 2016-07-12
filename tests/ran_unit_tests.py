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

"""Unit Test for the Ryu Action Node

01/07/16

"""

import unittest
import threading

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_4
from ryu.ofproto import ofproto_v1_5

import sys
sys.path.append("..")

from lib.packet_process import join
from lib.ver_check import version_check
from lib.diffuse_parse import proto_check
from lib.diffuse_parse import ipv4_to_int

from ran import *
from unittest.mock import patch, Mock

class VersionCheckTest(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_version_valid(self):
        """Verify correct version is returned for valid input"""
        self.assertEqual(version_check(0x04), 'OF13')
        self.assertEqual(version_check(0x05), 'OF14')
        self.assertEqual(version_check(0x06), 'OF15')

    def test_version_invalid(self):
        """Verify incorrect version is returned for invalid input"""
        self.assertEqual(version_check(0x03), 0)
        self.assertEqual(version_check('hello'), 0)
        self.assertEqual(version_check(None), 0)
        self.assertEqual(version_check(3), 0)


class PacketProcessTest(unittest.TestCase):

    def test_join_valid_array(self):
        array = ['01', '02', '03', '04', '05']
        len_array = len(array)
        offset = 0
        j = join(array, offset, len_array)
        self.assertEqual(j, '0102030405')

    def test_join_valid_offset(self):
        array = ['01', '02', '03', '04', '05']
        len_array = len(array)
        offset = 2
        j = join(array, offset, len_array)
        self.assertEqual(j, '030405')

    def test_join_valid_len(self):
        array = ['01', '02', '03', '04', '05']
        len_array = 2
        offset = 0
        j = join(array, offset, len_array)
        self.assertEqual(j, '0102')

    def test_join_invalid_int(self):
        array = 5
        offset = 3
        self.assertRaises(TypeError, join, array, offset, 1)

    def test_join_invalid_none(self):
        array = None
        offset = 0
        len_array = 1
        self.assertRaises(TypeError, join, array, offset, len_array)


class DiffuseParserTest(unittest.TestCase):

    def test_proto_check_tcp(self):
        proto = 6
        p = proto_check(proto)
        self.assertEqual(p, 'tcp')

    def test_proto_check_udp(self):
        proto = 17
        p = proto_check(proto)
        self.assertEqual(p, 'udp')

    def test_proto_check_other(self):
        proto = 122
        p = proto_check(proto)
        self.assertEqual(p, None)

    def test_proto_check_invalid_string(self):
        proto = 'hello'
        p = proto_check(proto)
        self.assertEqual(p, None)

    def test_ipv4_to_int_valid_ip(self):
        ip = '1.1.1.1'
        i = ipv4_to_int(ip)
        self.assertEqual(i, 16843009)

    def test_ipv4_to_int_invalid_input_int(self):
        ip = 0
        self.assertRaises(Exception, ipv4_to_int, ip)

    def test_ipv4_to_int_invalid_input_list(self):
        ip = ['1', '2']
        self.assertRaises(Exception, ipv4_to_int, ip)

    def test_ipv4_to_int_invalid_ip(self):
        ip = 'a.b.c.d'
        self.assertRaises(Exception, ipv4_to_int, ip)


class RanTest(unittest.TestCase):

    def setUp(self):
        self.ran = RAN()
        pass

    def tearDown(self):
        pass

    def test_message_converter_udp(self):
        max_ver = "OF13"
        parameter_set = {'PROTO': '11',
                         'SRC_PORT': '0001',
                         'DST_PORT': '0001',
                         'SRC_IPV4': '01010101',
                         'DST_IPV4': '01010101'
                         }
        x = RAN.msg_converter(parameter_set, max_ver)
        print(x)
        if ('eth_type', 2048) not in x:
            self.fail('Wrong eth_type')
        if ('ip_proto', 17) not in x:
            self.fail('Wrong ip_proto')
        if ('udp_src', 1) not in x:
            self.fail('Wrong udp_src')
        if ('udp_dst', 1) not in x:
            self.fail('Wrong udp_dst')
        if ('ipv4_src', 16843009) not in x:
            self.fail('wrong ipv4_src')
        if ('ipv4_dst', 16843009) not in x:
            self.fail('wrong ipv4_dst')

        pass

    def test_socket_tcp(self):
        ran = RAN(app_manager.RyuApp)
        sock = ran.socket_tcp()
        IP = '0.0.0.0'
        PORT = 5000

        if IP and PORT not in sock:
            self.fail('Wrong Address')
        if sock.proto != 0:
            self.fail('Wrong protocol')
        pass


    def test_time_now(self):
        x = RAN.time_now()
        pass

if __name__ == '__main__':
    unittest.main()
