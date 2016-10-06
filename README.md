RAN v1.01
==========
The Ryu Action Node (RAN) is a prioritisation tool for implementing Remote Action Protocol (RAP) messages on the SDN network.

NEW FEATURES IN THIS VERSION
----------------------------

- RAN separated from Simple_Switch_13
- Supports OF1.3 and OF1.4
- Supports Multi-Message
- Supports Multi-Version

INTRODUCTION
------------
This is the README for the RAN v1.01

This README gives a brief overview on how to install and setup the RAN using the FCN.
Example config files are provided.

For more information regarding the RAN and FCN refer to the technical report here:

[Supporting SDN and OpenFlow within DIFFUSE](http://caia.swin.edu.au/reports/160429A/CAIA-TR-160429A.pdf)

[Developing a Fake Classifier Node for DIFFUSE](http://caia.swin.edu.au/reports/160422A/CAIA-TR-160422A.pdf)

For an updated RAN check:

   <http://caia.swin.edu.au/urp/diffuse/sdn>

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

INSTALLATION
------------
### INSTALLING RYU
Get the latest release of the SDN DIFFUSE Ryu Action node from: 

<http://caia.swin.edu.au/urp/diffuse/sdn>
    
The latest release of RYU can be found on:

<https://osrg.github.io/ryu/>

### Download and build

Installing Ryu Prerequisites

```sh
    $ sudo apt-get update
    $ sudo apt-get install python-eventlet python-routes python-webob python-paramiko
```

Ryu can be downloaded from pip or Github.

```sh
    $ pip install ryu
```

or

```sh
    $ git clone git://github.com/osrg/ryu.git
    $ cd ryu
    $ python ./setup.py install
```

__INSTALLING THE RAN__

Just download ran-1.01.tar.gz and uncompress it.

```sh
    $ tar -zxvf ran-1.01.tar.gz
    $ cd ran-1.01
```
CONFIG FILE
-----------
The RAN will import class configurations from a conf.ini file in the RAN directory
An example conf.ini file has been provided.

The conf.ini will look similar to this:

    [SETTINGS]
    port = 5000
    host =
    table_id = 0
    protocol = TCP

    [default]
    queue = 0
    
    [class1]
    queue = 0
    type = drop
    meterid = 1
    rate = 20000
    
    [class2]
    queue = 1
    type = dscp
    dscp = 3
    meterid = 2
    rate = 30000

UPDATING
--------
__Ryu Updates__

```sh
    $ cd ryu
    $ git pull
```

RAN TESTBED
-----------

1. Change the directory to the RAN

   ```sh
       $ cd ran-1.01
   ```
    
2. Configure the `conf.ini` file as desired

3. Run the ryu-manager with the RAN using

   ```sh
       $ ryu-manager ./ran.py
   ```

Also Included are the Simple Switch and REST Route Northbound Applications running on SDN Flow Table 1. To run these applications concurrently with the RAN, just add the path to file.

### Simple Switch
The Simple Switch Application does not require any additional configuration.

```sh
    $ ryu-manager ./ran.py ./tests/mod_simple_switch_13.py
```

### REST Router
The REST Router Application will require additional setup configurations such as IP and routes. Refer to the [Ryu SDN Framework](http://osrg.github.io/ryu/resources.html#books) ebook for examples.

```sh
    $ ryu-manager ./ran.py ./tests/mod_rest_router.py
```

COMMANDS
--------
__Open vSwitch 2.3.0 Commands:__

```sh
    # Set bridge OpenFlow version
    $ ovs-vsctl set Bridge s1 protocol=OpenFlow13
    # Dump flow table rules
    $ ovs-ofctl -O OpenFlow13 dump-flows s1 
    # Dump flow meters
    $ ovs-ofctl -O OpenFlow13 dump-meters s1
```

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
