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
"""Unit Test for the Ryu Action Node

01/07/16

"""

import unittest
import sys
sys.path.append("..")

from lib.packet_process import join
from lib.packet_process import version_check
from lib.packet_process import proto_check
from lib.packet_process import ipv4_to_int
from lib.packet_process import time_now
from lib.packet_process import header_offset_check
from lib.packet_process import template_check
from lib.packet_process import msg_check
from ran import *


class PacketProcessTest(unittest.TestCase):

    def setUp(self):
        pass

    def test_join_valid_array(self):
        """Verify array conversion is correct for correct array

        """
        array = ['01', '02', '03', '04', '05']
        len_array = len(array)
        offset = 0
        j = join(array, offset, len_array)
        self.assertEqual(j, '0102030405')

    def test_join_valid_offset(self):
        """Verify array conversion correct given an offset

        """
        array = ['01', '02', '03', '04', '05']
        len_array = len(array)
        offset = 2
        j = join(array, offset, len_array)
        self.assertEqual(j, '030405')

    def test_join_valid_len(self):
        """Verify array conversion is correct given a length

        """
        array = ['01', '02', '03', '04', '05']
        len_array = 2
        offset = 0
        j = join(array, offset, len_array)
        self.assertEqual(j, '0102')

    def test_join_invalid_int(self):
        """Verify array conversion raises error for integer input

        """
        array = 5
        offset = 3
        self.assertRaises(TypeError, join, array, offset, 1)

    def test_join_invalid_none(self):
        """Verify array conversion raises error for no input

        """
        array = None
        offset = 0
        len_array = 1
        self.assertRaises(TypeError, join, array, offset, len_array)

    def test_header_offset_valid(self):
        """Verify correct offset for each header name

        """
        header_name = ['ver',
                       'set_len',
                       'seq_no',
                       'set_id',
                       'm_len',
                       'time']

        header_length = {'ver': 2,
                         'm_len': 2,
                         'seq_no': 4,
                         'time': 4,
                         'set_id': 2,
                         'set_len': 2}

        for __, name in enumerate(header_name):
            self.assertEqual(header_offset_check(name), header_length[name])

    def test_header_offset_invalid(self):
        """Verify correct output for invalid header name

        """
        self.assertEqual(header_offset_check('123'), 0)
        self.assertEqual(header_offset_check(123), 0)
        self.assertEqual(header_offset_check(None), 0)

    def test_template_check_valid(self):
        """Verify correct Template IDs

        """
        template_name = ['0001',
                         '0002',
                         '0003',
                         '0004',
                         '0005',
                         '0006',
                         '0007',
                         '0008',
                         '0009',
                         '0010',
                         '0011',
                         '000a',
                         '000b',
                         '000c',
                         '000d',
                         '000e',
                         '000f',
                         '8000',
                         '8001',
                         '8002',
                         '8003',
                         'c000']

        template_id = {'0001': 'SRC_IPV4',
                       '0002': 'DST_IPV4',
                       '0003': 'SRC_PORT',
                       '0004': 'DST_PORT',
                       '0005': 'PROTO',
                       '0006': 'SRC_IPV6',
                       '0007': 'DST_IPV6',
                       '0008': 'IPV4_TOS',
                       '0009': 'IPv6_FLOW_LABEL',
                       '0010': 'PKT_COUNT',
                       '0011': 'KBYTE_COUNT',
                       '000a': 'CLASS_LABEL',
                       '000b': 'MATCH_DIR',
                       '000c': 'MSG_TYPE',
                       '000d': 'TIME_TYPE',
                       '000e': 'TIMEOUT',
                       '000f': 'ACT_FLAG',
                       '8000': 'ACT',
                       '8001': 'ACT_PAR',
                       '8002': 'CLASS_NAME',
                       '8003': 'EXPORT_NAME',
                       'c000': 'CLASS_TAG'}

        for __, name in enumerate(template_name):
            self.assertEqual(template_check(name), template_id[name])

    def test_template_id_invalid(self):
        """Verify correct output template ID for invalid input

        """
        self.assertEqual(template_check('123'), '0000')
        self.assertEqual(template_check(123), '0000')
        self.assertEqual(template_check(None), '0000')

    def test_msg_check_valid(self):
        """Verify correct output msg ID for valid input

        """
        msg_name = ['T_ID',
                    'T_FLAG',
                    'CLASS_NAME',
                    'MSG_TYPE',
                    'SRC_IPV4',
                    'DST_IPV4',
                    'SRC_PORT',
                    'DST_PORT',
                    'PROTO',
                    'PKT_COUNT',
                    'KBYTE_COUNT',
                    'TIME_TYPE',
                    'TIMEOUT',
                    'ACT',
                    'ACT_FLAG',
                    'ACT_PAR']

        msg_length = {'T_ID': 0,
                      'T_FLAG': 0,
                      'CLASS_NAME': 8,
                      'MSG_TYPE': 1,
                      'SRC_IPV4': 4,
                      'DST_IPV4': 4,
                      'SRC_PORT': 2,
                      'DST_PORT': 2,
                      'PROTO': 1,
                      'PKT_COUNT': 4,
                      'KBYTE_COUNT': 4,
                      'TIME_TYPE': 1,
                      'TIMEOUT': 2,
                      'ACT': 8,
                      'ACT_FLAG': 2,
                      'ACT_PAR': 8}

        act_par = [len('00000000')]

        for __, name in enumerate(msg_name):
            self.assertEqual(msg_check(name, act_par), msg_length[name])

    def test_msg_check_invalid(self):
        """Verify Msg Check for invalid Template IDs

        """
        self.assertEqual(msg_check("AAA"), 0)
        self.assertEqual(msg_check(123), 0)
        self.assertEqual(msg_check(0x2), 0)
        self.assertEqual(msg_check(None), 0)

    def test_version_valid(self):
        """Verify correct version is returned for valid input

        """
        self.assertEqual(version_check(0x04), 'OF13')
        self.assertEqual(version_check(0x05), 'OF14')
        self.assertEqual(version_check(0x06), 'OF15')

    def test_version_invalid(self):
        """Verify incorrect version is returned for invalid input

        """
        self.assertEqual(version_check(0x03), 0)
        self.assertEqual(version_check(0x02), 0)
        self.assertEqual(version_check(0x01), 0)
        self.assertEqual(version_check('123'), 0)
        self.assertEqual(version_check(None), 0)
        self.assertEqual(version_check(3), 0)

    def test_proto_check_tcp(self):
        """Verify protocol 6 is TCP

        """
        proto = 6
        p = proto_check(proto)
        self.assertEqual(p, 'tcp')

    def test_proto_check_udp(self):
        """Verify protocol 17 is UDP

        """
        proto = 17
        p = proto_check(proto)
        self.assertEqual(p, 'udp')

    def test_proto_check_invalid(self):
        """Verify any other protocol input gives None

        """
        self.assertEqual(proto_check('123'), None)
        self.assertEqual(proto_check(123), None)
        self.assertEqual(proto_check(None), None)

    def test_ipv4_to_int_valid_ip(self):
        """Verify IPv4 correctly converted

        """
        ip = '1.1.1.1'
        expected = 16843009
        self.assertEqual(ipv4_to_int(ip), expected)

    def test_ipv4_to_int_invalid_input_int(self):
        """Verify IPv4 correctly raises exception for invalid int

        """
        ip = 0
        self.assertRaises(Exception, ipv4_to_int, ip)

    def test_ipv4_to_int_invalid_input_list(self):
        """Verify IPv4 correctly raises exception for list input

        """
        ip = ['1', '2']
        self.assertRaises(Exception, ipv4_to_int, ip)

    def test_ipv4_to_int_invalid_ip(self):
        """Verify IPv4 correctly raises exception for other invalid IP

        """
        self.assertRaises(Exception, ipv4_to_int, 'a.b.c.d')
        self.assertRaises(Exception, ipv4_to_int, None)

    def test_ipv4_to_int_invalid_out_of_range(self):
        """Verify IPv4 correctly raises exception for out of range IP

        """
        ip = '256.256.256.256'
        self.assertRaises(Exception, ipv4_to_int, ip)


class RanTest(unittest.TestCase):

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_message_converter(self):
        """Verify message converter works with all parameters

        """
        max_ver = "OF13"
        parameter_set = {'PROTO': '11',
                         'SRC_PORT': '0001',
                         'DST_PORT': '0001',
                         'SRC_IPV4': '01010101',
                         'DST_IPV4': '01010101'
                         }
        x = RAN.msg_converter(parameter_set, max_ver)
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

    def test_class_name_conversion(self):
        """Verify hex string converts successfully to ASCII

        """
        flow_set = {'CLASS_TAG': [0, '48656c6c6f']}
        class_name = RAN.class_name_conversion(flow_set)
        self.assertEqual(class_name, b'Hello')

if __name__ == '__main__':
    unittest.main()
