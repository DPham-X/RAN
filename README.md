RAN v1.04
==========
The Ryu Action Node (RAN) is a prioritisation tool for implementing Remote Action Protocol (RAP) messages on the SDN network.

Features
--------

- Supports OpenFlow 1.3, 1.4
- Supports Multi Message RAP
- Supports Multi Version SDN switches

Running Ryu with the RAN
------------------------

    $ cd RAN
    $ ryu-manager ./ran.py
  
Installing the RAN
------------------

  $ git clone https://github.com/XykotiC/RAN.git
   
Installing RYU
--------------

### Download and build

Ryu can be downloaded from Github.

    $ pip install ryu

or

    $ git clone git://github.com/osrg/ryu.git
    $ cd ryu
    $ python ./setup.py install

### Prerequisites

    python-eventlet
    python-routes
    python-webob
    python-paramiko

`$ sudo apt-get update`

`$ sudo apt-get install python-eventlet python-routes python-webob python-paramiko`

Updating Ryu
------------

    $ cd ryu
    $ git pull


