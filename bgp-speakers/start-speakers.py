#!/usr/bin/python

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Node, Controller, OVSSwitch, OVSController, RemoteController
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.link import Intf, Link

import time
import os

class BgpSecNetwork( Node ):
    def config( self, **params ):
        super( BgpSecNetwork, self).config( **params )
        self.cmd( 'sysctl net.ipv4.ip_forward=1' )

    def terminate( self ):
        self.cmd( 'sysctl net.ipv4.ip_forward=0' )
        super( BgpSecNetwork, self ).terminate()


class NetworkTopo( Topo ):
    def build( self, **_opts ):

        #ipR1 = '192.168.10.1/24'
        #ipR2 = '192.168.11.1/24' 
        #router1 = self.addNode( 'r1', cls=BgpSecNetwork, ip=ipR1 )
	#router2 = self.addNode( 'r2', cls=BgpSecNetwork, ip=ipR2 )
	sw1 = self.addSwitch('sw1',dpid='1000000000000001')

        h1 = self.addHost( 'h1', ip='10.251.11.157/24', defaultRoute='via 10.251.11.156',dpid='0000000000000001')
        h2 = self.addHost( 'h2', ip='10.251.11.158/24', defaultRoute='via 10.251.11.156',dpid='0000000000000002')
	h3 = self.addHost( 'h3', ip='10.251.11.159/24', defaultRoute='via 10.251.11.156',dpid='0000000000000003')
	h4 = self.addHost( 'h4', ip='10.251.11.160/24', defaultRoute='via 10.251.11.156',dpid='0000000000000004')
	#self.addLink(h1,router1,intfName1='r1-eth0')
	self.addLink(h1,sw1,intfName1='eth0')
	self.addLink(h2,sw1,intfName1='eth0')
	self.addLink(h3,sw1,intfName1='eth0')
	self.addLink(h4,sw1,intfName1='eth0')
	#self.addLink(switch1,router1,intfName1='s1-eth0',intfName2='r1-eth1',params2={'ip':'10.10.10.1/24'})
        #self.addLink(switch1,router2,intfName1='s1-eth1',intfName2='r2-eth1',params2={'ip':'10.10.10.2/24'})	
        #self.addLink( self, 'sw1', cls='BgpSecNetwork', intfName1='s1-eth3' )
	#intfName = 'bgp-65001'
    	#info( 'Adding hardware interface to switch', '\n' )
    	#_intf = Intf( intfName, node=sw1 )
        #c0 = Controller( 'c0', port=6633 )

def run():
    topo = NetworkTopo()
    #net = Mininet(topo=topo)
    net = Mininet(controller=lambda name: RemoteController( name, ip='10.251.11.156' ), switch=OVSSwitch,topo=topo)
    #c1 = net.addController('c0', ip='10.251.11.156', port=6653)
    #net.addController('c0')
    #switch = net.h1   
    #switch = net.switches[ 0 ]   
    #_intf = Intf( 'veth0', node=switch )
    net.start()
    info( 'Initial routing table on router:\n' )
    #info( net[ 'r1' ].cmd( 'route' ) )
    #info( net[ 'r2' ].cmd( 'route' ) )

    #r1=net.getNodeByName('r1')
    #r2=net.getNodeByName('r2')
    info('Starting zebra and bgp deamon:\n')

    #r1.cmd('/usr/sbin/zebra -f /home/rcosta/bgpsecx/bgp-speakers/r1-zebra.conf -d -i /tmp/r1-zebra.pid')
    #r2.cmd('/usr/sbin/zebra -f /home/rcosta/bgpsecx/bgp-speakers/r2-zebra.conf -d -i /tmp/r2-zebra.pid')
    time.sleep(2)
    #
    #r1.cmd('/usr/sbin/bgpd -f /home/rcosta/bgpsecx/bgp-speakers/r1-bgpd.conf -d -i /tmp/r1-bgpd.pid')
    #r2.cmd('/usr/sbin/bgpd -f /home/rcosta/bgpsecx/bgp-speakers/r2-bgpd.conf -d -i /tmp/r2-bgpd.pid')
   
    CLI( net )
    net.stop()
    os.system("killall -9 bgpd zebra")
    os.system("rm -f *api*")
    os.system("rm -f *interface*")

if __name__ == '__main__':
    setLogLevel( 'info' )
    run()

