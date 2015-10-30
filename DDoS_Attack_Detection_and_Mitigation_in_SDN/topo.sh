#!/usr/bin/python


from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSKernelSwitch, OVSLegacyKernelSwitch, UserSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.link import Link, TCLink

def topology():
    "Create a network."
    net = Mininet( controller=RemoteController, link=TCLink, switch=OVSKernelSwitch )

    print "*** Creating nodes"
    c1 = net.addController('controller', controller=RemoteController, port=6633)
    h1 = net.addHost( 'h1', mac='0a:00:11:11:11:11', ip='10.0.0.1/24' )
    h2 = net.addHost( 'h2', mac='0a:00:22:22:22:22', ip='10.0.0.2/24' )
    h3 = net.addHost( 'h3', mac='0a:00:33:33:33:33', ip='10.0.0.3/24' )
    h4 = net.addHost( 'h4', mac='0a:00:44:44:44:44', ip='10.0.0.4/24' )
    h5 = net.addHost( 'h5', mac='0a:00:55:55:55:55', ip='10.0.0.5/24' )
    h6 = net.addHost( 'h6', mac='0a:00:66:66:66:66', ip='10.0.0.6/24' )
    s1 = net.addSwitch( 's1', listenPort=6634, dpid='0000000000000001' )


    print "*** Creating links"
    net.addLink(s1, h1, 1, 0)
    net.addLink(s1, h2, 2, 0)
    net.addLink(s1, h3, 3, 0)
    net.addLink(s1, h4, 4, 0)
    net.addLink(s1, h5, 5, 0)
    net.addLink(s1, h6, 6, 0)

    net.build()


    print "*** Starting network"
    s1.start( [c1] )
    c1.start

    print "*** Running CLI"
    CLI( net )

    print "*** Stopping network"
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    topology()

