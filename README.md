# RAN_v400
This is the RYU ACTION NODE v4.00 which currently supports OpenFlow 1.3 and 
OpenFlow 1.4.

## Installing RYU

### Download and build

Ryu can be downloaded from Github.

git clone git://github.com/osrg/ryu.git
cd ryu

### Prerequisites

    python-eventlet
    python-routes
    python-webob
    python-paramiko

sudo apt-get update
sudo apt-get install python-eventlet python-routes python-webob python-paramiko

### Updating Ryu

cd ryu

git pull

### Running Ryu and the RAN
ryu-manager ./ran_v400.py
