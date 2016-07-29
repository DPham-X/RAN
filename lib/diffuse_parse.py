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


def proto_check(proto):
    """Checks if protocol is TCP or UDP

    Parameters
    ----------
    proto: int
        The protocol number in the FCN/CN message
    Returns
    -------
        The protocol name if TCP/UDP else returns nothing

    """
    # Check for TCP
    if proto == 6:
        return 'tcp'
    # Check for UDP
    elif proto == 17:
        return 'udp'
    else:
        return None


def ipv4_to_int(string):
    """Converts an IPv4 string to integer

    Parameters
    ----------
    string: str eg. '1.1.1.1'
        The IPv4 string
    Returns
    -------
        The integer representation of the IPv4 string

    """
    try:
        ip = string.split('.')
        assert len(ip) == 4
        i = 0
        for b in ip:
            b = int(b)
            i = (i << 8) | b
    except Exception as e:
        raise Exception('Invalid input IP:', e)
    return i
