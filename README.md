RAN v1.01
==========
The Ryu Action Node (RAN) is a prioritisation tool for implementing Remote Action Protocol (RAP) messages on the SDN network.

INTRODUCTION
------------
This is the README for the RAN v1.01

This README gives a brief overview on how to install and setup the RAN using the FCN.
Example config files are provided.

For more information regarding the RAN and FCN refer to the technical report here:

    http://caia.swin.edu.au/reports/160429A/CAIA-TR-160429A.pdf
    http://caia.swin.edu.au/reports/160422A/CAIA-TR-160422A.pdf

For an updated RAN and FCN check:

    https://github.com/XykotiC/RAN/

CONFIG FILE
-----------
The RAN will import class configurations from a conf.ini file in the RAN directory
An example conf.ini file has been provided.
   
NEW FEATURES IN THIS VERSION
----------------------------

- Supports OpenFlow 1.3, 1.4
- Supports Multi Message RAP
- Supports Multi Version SDN switches

RYU ACTION NODE TEST BED
------------------------
RAN Requirements:
    
    Ryu Framework
    OpenFlow SDN Switch
    Python 2.7
    
Ryu Prerequisites

    python-eventlet
    python-routes
    python-webob
    python-paramiko

Installation
------------
__INSTALLING RYU__

    $ git clone https://github.com/XykotiC/RAN.git
From the RYU web page:

    https://osrg.github.io/ryu/

Download and build

Ryu can be downloaded from pip or Github.

    $ pip install ryu

or

    $ git clone git://github.com/osrg/ryu.git
    $ cd ryu
    $ python ./setup.py install

Installing Prerequisites

    $ sudo apt-get update
    $ sudo apt-get install python-eventlet python-routes python-webob python-paramiko

__INSTALLING THE RAN__

    $ git clone https://github.com/XykotiC/RAN.git

RUNNING RYU WITH THE RAN
------------------------

    $ cd RAN
    $ ryu-manager ./ran.py

UPDATE
------
__Ryu Updates__

    $ cd ryu
    $ git pull

__RAN Updates__

    $ cd RAN
    $ git pull

RAN TESTBED
-----------
1. First configure the `conf.ini` file


LICENSE
-------

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
