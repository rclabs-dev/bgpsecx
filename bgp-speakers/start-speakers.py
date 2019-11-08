#!/usr/bin/python

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Node, RemoteController, OVSSwitch
from mininet.log import setLogLevel, info
from mininet.cli import CLI
import time
import os

class LinuxRouter( Node ):
    def config( self, **params ):
        super( LinuxRouter, self).config( **params )
        self.cmd( 'sysctl net.ipv4.ip_forward=1' )

    def terminate( self ):
        self.cmd( 'sysctl net.ipv4.ip_forward=0' )
        super( LinuxRouter, self ).terminate()


class NetworkTopo( Topo ):
    def build( self, **_opts ):

        ipR1 = '192.168.10.1/24'
        ipR2 = '192.168.11.1/24' 
        router1 = self.addNode( 'r1', cls=LinuxRouter, ip=ipR1 )
	router2 = self.addNode( 'r2', cls=LinuxRouter, ip=ipR2 )
	switch1 = self.addSwitch('s1',dpid='1000000000000001')

	
        
        h1 = self.addHost( 'h1', ip='192.168.10.2/24', defaultRoute='via 192.168.10.1',dpid='0000000000000001')
        h2 = self.addHost( 'h2', ip='192.168.11.2/24', defaultRoute='via 192.168.11.1',dpid='0000000000000002')


	self.addLink(h1,router1,intfName1='r1-eth0')
	self.addLink(h2,router2,intfName1='r2-eth0')
	self.addLink(switch1,router1,intfName1='s1-eth0',intfName2='r1-eth1',params2={'ip':'10.10.10.1/24'})
        self.addLink(switch1,router2,intfName1='s1-eth1',intfName2='r2-eth1',params2={'ip':'10.10.10.2/24'})	

def run():
    topo = NetworkTopo()
    net = Mininet(controller=RemoteController,topo=topo)
    c1 = net.addController('c1', ip='10.251.11.156', port=6653)
    net.start()
    info( 'Initial routing table on router:\n' )
    info( net[ 'r1' ].cmd( 'route' ) )
    info( net[ 'r2' ].cmd( 'route' ) )

    r1=net.getNodeByName('r1')
    r2=net.getNodeByName('r2')
    info('Starting zebra and bgp deamon:\n')

    r1.cmd('/usr/sbin/zebra -f /home/rcosta/bgpsecx/bgp-speakers/r1-zebra.conf -d -i /tmp/r1-zebra.pid')
    r2.cmd('/usr/sbin/zebra -f /home/rcosta/bgpsecx/bgp-speakers/r2-zebra.conf -d -i /tmp/r2-zebra.pid')
    time.sleep(2)
    #
    r1.cmd('/usr/sbin/bgpd -f /home/rcosta/bgpsecx/bgp-speakers/r1-bgpd.conf -d -i /tmp/r1-bgpd.pid')
    r2.cmd('/usr/sbin/bgpd -f /home/rcosta/bgpsecx/bgp-speakers/r2-bgpd.conf -d -i /tmp/r2-bgpd.pid')
   
    CLI( net )
    net.stop()
    os.system("killall -9 bgpd zebra")
    os.system("rm -f *api*")
    os.system("rm -f *interface*")

if __name__ == '__main__':
    setLogLevel( 'info' )
    run()

