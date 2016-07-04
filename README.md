# RAN_v1.04
This is the RYU ACTION NODE v4.00 which currently supports OpenFlow 1.3 and
OpenFlow 1.4.

## Installing RYU

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

### Updating Ryu

    $ cd ryu
    $ git pull

### Running Ryu and the RAN

    $ ryu-manager ./ran_v400.py
