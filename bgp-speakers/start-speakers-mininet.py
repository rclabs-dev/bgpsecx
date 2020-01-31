#!/usr/bin/python

"""
This code creates bgp speakers in each created hosts.
"""

import re
import sys
import time
import os

from mininet.cli import CLI
from mininet.log import setLogLevel, info, error
from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSController
from mininet.link import Intf
from mininet.topolib import TreeTopo
from mininet.topo import Topo
from mininet.util import quietRun

def checkIntf( intf ):
    "Make sure intf exists and is not configured."
    config = quietRun( 'ifconfig %s 2>/dev/null' % intf, shell=True )
    if not config:
        error( 'Error:', intf, 'does not exist!\n' )
        exit( 1 )
    ips = re.findall( r'\d+\.\d+\.\d+\.\d+', config )
    if ips:
        error( 'Error:', intf, 'has an IP address,'
               'and is probably in use!\n' )
        exit( 1 )

class NetworkTopo( Topo ):
    def build( self, **_opts ):
	sw1 = self.addSwitch('sw1',dpid='1000000000000001')
        h1 = self.addHost( 'h1', ip='192.168.10.10/24', defaultRoute='via 192.168.10.1')
        h2 = self.addHost( 'h2', ip='192.168.10.11/24', defaultRoute='via 192.168.10.1')
        h3 = self.addHost( 'h3', ip='192.168.10.12/24', defaultRoute='via 192.168.10.1')
        h4 = self.addHost( 'h4', ip='192.168.10.13/24', defaultRoute='via 192.168.10.1')
	self.addLink(h1,sw1,intfName1='eth0')
	self.addLink(h2,sw1,intfName1='eth0')
	self.addLink(h3,sw1,intfName1='eth0')
	self.addLink(h4,sw1,intfName1='eth0')
 
if __name__ == '__main__':
    setLogLevel( 'info' )
    info( '*** Creating network\n' )
    net = Mininet( topo=NetworkTopo(), controller=lambda name: RemoteController( name, ip='10.251.11.156' ) )
    info( '*** Note: you may need to reconfigure the interfaces for '
          'the Mininet hosts:\n', net.hosts, '\n' )
    net.start()
    os.system("ifconfig -a sw1 192.168.10.1/24 up")
    info( '*** Starting BGP Speakers\n' )  
    time.sleep(3)
    bgp1=net.getNodeByName('h1')
    bgp2=net.getNodeByName('h2')
    bgp1.cmd('/usr/sbin/bgpd -d -l 192.168.10.10 -A 10.251.11.156 -f /etc/quagga/bgpd-1.conf -i /tmp/bgpd-1.pid')
    time.sleep(3)
    bgp2.cmd('/usr/sbin/bgpd -d -l 192.168.10.11 -A 10.251.11.156 -f /etc/quagga/bgpd-2.conf -i /tmp/bgpd-2.pid')
    CLI( net )
    net.stop()
    os.system("killall -9 bgpd")
