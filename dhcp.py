#!/usr/bin/env python3
from mininet.topo import Topo
from mininet.net import Mininet

from mininet.link import TCLink
from mininet.log import setLogLevel

from mininet.clean import Cleanup
from mininet.cli import CLI

from mininet.node import OVSController

import scapy.all as scapy

import argparse

import time

parser = argparse.ArgumentParser(description='DHCP server and snooping')
parser.add_argument('--snoop', required=False, type=bool, default=False, help='Snoop for DHCP servers')
parser.add_argument('--stop', required=False, type=bool, default=False, help='Stop malicious DHCP/DNS servers')

class DhcpTopo(Topo):
    "Three switch topology"
    def build( self ):
        "Create custom topo."
        # Add hosts and switches
        # h1 is a host with no IP address
        h1 = self.addHost('h1', ip=None)
        # DHCP servers have static IP addresses
        h2 = self.addHost('h2', ip='10.0.0.102/24')
        h3 = self.addHost('h3', ip='10.0.0.103/24')
        snooper = self.addHost('snooper', ip='10.0.0.100/24')
        # add a switch for the hosts
        s1 = self.addSwitch('s1')

        # Add host links
        self.addLink(h1, s1, cls=TCLink, delay='10ms')
        # delay is 200ms to make it easier to see the effect of the competing rogue DHCP server
        self.addLink(h2, s1, cls=TCLink, bw=1, delay='200ms', use_htb=True)
        self.addLink(h3, s1, cls=TCLink, delay='10ms')
        # add a link to the snooper
        self.addLink(snooper, s1, cls=TCLink, delay='10ms')

def mountPrivateResolvconf(host):
    "Create/mount private /etc/resolv.conf for host"
    # create a private /etc for the host
    etc = '/tmp/etc-%s' % host
    host.cmd('mkdir -p', etc)
    # populate /etc in the host
    host.cmd('mount --bind /etc', etc )
    host.cmd('mount -n -t tmpfs tmpfs /etc' )
    # create a symlink to the original /etc
    host.cmd('ln -s %s/* /etc/' % etc )
    # remove the original resolv.conf
    host.cmd('rm /etc/resolv.conf' )
    # copy the private resolv.conf
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
    # hashtag is a wildcard for all domains, so we can redirect all requests to the evil web server at h3
    host.cmd( '/usr/sbin/dnsmasq -k -A /#/%s 1>/tmp/dns.log 2>&1 &' %  host.IP() )

def stopFakeDNS( host ):
    "Stop Fake DNS server"
    print( '* Stopping fake DNS server', host, 'at', host.IP(), '\n' )
    host.cmd( 'kill %dnsmasq' )

# Evil web server

def startEvilWebServer( host ):
    "Start evil web server"
    print( '* Starting web server', host, 'at', host.IP(), '\n' )
    # all domain requests will be redirected to the evil web server
    webdir = '/tmp/evilwebserver'
    # remove the old webdir and create a new one
    host.cmd('rm -rf', webdir )
    host.cmd( 'mkdir -p', webdir )
    # create an index.html file
    html_file = (
        '<html>',
        '<body>',
        '<h1>Your traffic has been deemed suspicious, please login to continue browsing</h1>',
        '<form action="login">',
        'e-mail: <input type="text" name="email"><br>',
        'password: <input type="password" name="password"><br>',
        '<input type="submit" value="Sign In">',
        '</form>',
        '<-- YOU HAVE BEEN PWNED BY LE EPIC HAXXOR!!! >:0 -->',
        '</body>',
        '</html>'
    )
    with open( webdir + '/index.html', 'w' ) as f:
        f.write( '\n'.join( html_file ) )
    host.cmd( 'cd', webdir )
    # start the web server on port 80 (http)
    host.cmd( 'python3 -m http.server 80 >& /tmp/http.log &' )

def stopEvilWebServer( host ):
    "Stop evil web server"
    print( '* Stopping web server', host, 'at', host.IP(), '\n' )
    host.cmd( 'kill %python' )

# DHCP server functions and data
DHCPTemplate = """
start		10.0.0.10
end		10.0.0.90
option	subnet	255.255.255.0
option	domain	local
option	lease	180  # 3 minutes
"""

def makeDHCPconfig( filename, interface, gateway, dns ):
    # write a DHCP configuration file to /tmp/host-udhcpd.conf
    "Create a DHCP configuration file"
    config = (
        'interface %s' % interface,
        DHCPTemplate,
        'option router %s' % gateway,
        'option dns %s' % dns,
        '' )
    with open( filename, 'w' ) as f:
        f.write( '\n'.join( config ) )

def startDHCPserver( host, gateway, dns ):
    "Start DHCP server on host with specified DNS server"
    print( '* Starting DHCP server on', host, 'at', host.IP(), '\n' )
    dhcpConfig = '/tmp/%s-udhcpd.conf' % host
    makeDHCPconfig( dhcpConfig, host.defaultIntf(), gateway, dns )
    # start DHCP server with configuration file and log to /tmp/host-dhcp.log
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

# DHCP Snooping

def makeDHCPDiscover(sender):
    "Make a DHCPDISCOVER packet"
    # create a DHCPDISCOVER packet
    dhcp_discover = scapy.Ether(dst='ff:ff:ff:ff:ff:ff') / \
                    scapy.IP(src='0.0.0.0', dst='255.255.255.255') / \
                    scapy.UDP(sport=68, dport=67) / \
                    scapy.BOOTP(chaddr=sender.MAC()) / \
                    scapy.DHCP(options=[('message-type', 'discover'), 'end'])
    return dhcp_discover

def makeDHCPRequest(sender, server_ip):
    "Make a DHCPREQUEST packet"
    # create a DHCPREQUEST packet
    dhcp_request = scapy.Ether(dst='ff:ff:ff:ff:ff:ff') / \
                   scapy.IP(src='0.0.0.0', dst='255.255.255.255') / \
                     scapy.UDP(sport=68, dport=67) / \
                        scapy.BOOTP(chaddr=sender.MAC()) / \
                        scapy.DHCP(options=[('message-type', 'request'), 'end'])
    return dhcp_request

def save_dhcp_packet_to_file( dhcp_packet_type, packet ):
    "Save packet to file"
    filename = '/tmp/dhcp-%s-packet.pcap' % dhcp_packet_type
    with open( filename, 'wb' ) as f:
        f.write( bytes(packet) )

def create_dhcp_packet_send_command( dhcp_packet_type ):
    filename = '/tmp/send-dhcp-%s.py' % dhcp_packet_type
    packet_path = '/tmp/dhcp-%s-packet.pcap' % dhcp_packet_type
    py_file = (
        'import scapy.all as scapy',
        'packet = open("%s", "rb").read()' % packet_path,
        'scapy.sendp(packet)',
        'print("Sent %s packet")' % dhcp_packet_type.capitalize()
    )
    with open( filename, 'w' ) as f:
        f.write( '\n'.join( py_file ) )
    return filename

def getActiveDHCPServers( net, snooper ):
    "Print active DHCP servers"
    active_dhcp_servers = []
    # send a DHCPDISCOVER packet from snooper to all hosts
    print( '* Sending broadcast DHCPDISCOVER from snooper \n' )
    host_discover = makeDHCPDiscover( snooper )
    save_dhcp_packet_to_file( 'discover', host_discover )
    filename = create_dhcp_packet_send_command( 'discover' )
    print( snooper.cmd( 'python3', filename ) )
    # listen for DHCP offers
    print ( '* Listening for DHCP offers for 5 seconds \n' )
    sniffed = snooper.cmd( 'timeout 5s tcpdump -l -n -i', snooper.defaultIntf(), 'udp port 67 and port 68' )
    for line in sniffed.splitlines():
        if 'IP' in line:
            # reverse, split, and reverse again to remove the port number
            dhcp_server_socket = line.split(" ")[2]
            dhcp_server_socket = dhcp_server_socket[::-1]
            dhcp_server_ip = dhcp_server_socket.split(".", 1)[1]
            dhcp_server_ip = dhcp_server_ip[::-1]
            print( 'DHCP server at', dhcp_server_ip, 'is active' )    

            active_dhcp_servers.append(dhcp_server_ip)
    return active_dhcp_servers

def checkDHCPDNSservers( active_dhcp_servers, snooper ):
    "Check DHCP and DNS servers"
    potentially_malicious = []
    for dhcp_server_ip in active_dhcp_servers:
        #check if the DNS server is the same as the DHCP server
        #check dhcp server for dns server with scapy
        if ( checkifDNSserver( dhcp_server_ip, snooper ) ):
            print( 'DNS server is the same as the DHCP server, this may be malicious!' )
            potentially_malicious.append( dhcp_server_ip )
            
    return potentially_malicious

def checkifDNSserver( dns_server_ip, snooper ):
    "Check if the DNS server is the same as the DHCP server"
    # create a DNS query packet
    cmd = f'dig @{dns_server_ip} +short'
    snooper.cmd( cmd )
    rc = snooper.cmd( 'echo $?' )
    rc = int(rc.strip())
    if rc == 0:
        print( dns_server_ip, ' is a DNS server' )
        return True
    else:
        print( dns_server_ip, ' is not a DNS server' )
        return False

def setResolvconf( dns_server_ip, snooper ):
    "Set resolv.conf to a specific DNS server"
    print( '* Setting resolv.conf to', dns_server_ip, '\n' )
    snooper.cmd( 'echo "nameserver', dns_server_ip, '" > /etc/resolv.conf' )
    check = snooper.cmd( 'cat /etc/resolv.conf' )
    print( check )

def blockDHCPserver( dhcp_server_ip, switch ):
    "Block DHCP server"
    print( 'Blocking DHCP server', dhcp_server_ip )
    # block the DHCP server
    # add switch rule to block the DHCP server
    cmd = f"ovs-ofctl add-flow {switch.name} priority=100,dl_type=0x0800,nw_src={dhcp_server_ip},action=drop"
    switch.cmd( cmd )
    # test the block
    print( 'Testing the block...' )
    # ping the DHCP server
    result = switch.cmd( 'ping -c 1 -w 2', dhcp_server_ip )
    rc = switch.cmd( 'echo $?' )
    rc = int(rc.strip())
    if rc == 0:
        print( 'Block failed' )
    else:
        print( 'Block succeeded' )

def start_wireshark( host ):
    "Start Wireshark on host"
    host.cmd( 'wireshark &')

def main(args):
    snoopEnable = args.snoop
    stopPotentiallyMalicious = args.stop
    if stopPotentiallyMalicious and not snoopEnable:
        print ( 'Cannot stop malicious servers without snooping for them' )
        return

    Cleanup.cleanup()
    topo = DhcpTopo()

    net = Mininet(topo, controller=OVSController, link=TCLink, cleanup=True)
    net.addNAT(ip='10.0.0.1/24').configDefault()

    print("Started")

    h1 = net.get('h1')
    h2 = net.get('h2')
    h3 = net.get('h3')

    snooper = net.get('snooper')
    start_wireshark(snooper)
    start_wireshark(h1)
    print('Wireshark started... waiting for 10 seconds')
    time.sleep(10)

    s1 = net.get('s1')
    nat0 = net.get('nat0')

    net.start()

    mountPrivateResolvconf(h1)
    mountPrivateResolvconf(snooper)

    startDHCPserver(h2, nat0.IP(), '9.9.9.9') #dhcp server with dns that resolves to quad9
    startDHCPserver(h3, nat0.IP(), h3.IP()) # dhcp server with dns that resolves to itself
    startFakeDNS(h3)
    startEvilWebServer(h3)

    if snoopEnable:
        print ( 'Snooping for DHCP servers, Checking DNS servers, and blocking malicious servers' )
        active_dhcp_servers = getActiveDHCPServers(net, snooper)
        potentially_malicious = checkDHCPDNSservers(active_dhcp_servers, snooper)
        if stopPotentiallyMalicious:
            print ( 'Stopping malicious combination DHCP and DNS servers' )
            for bad_dhcp_server in potentially_malicious:
                blockDHCPserver(bad_dhcp_server, s1)
        else:
            print ( 'Not stopping malicious DHCP servers' )
            print ( 'Run with --stop to stop malicious DHCP servers' )
    else:
        print ( 'Not snooping for DHCP servers' )
        print ( 'Run with --snoop to snoop for DHCP servers, monitor DNS servers, and stop malicious servers' )

    # start xterm for h1
    h1.cmd('xterm &')
    # demonstrate DHCP client with dhclient on h1
    CLI(net)

    unmountPrivateResolvconf(h1)
    unmountPrivateResolvconf(snooper)
    stopDHCPserver(h2)
    stopDHCPserver(h3)
    stopFakeDNS(h3)
    stopEvilWebServer(h3)
    net.stop()


if __name__ == "__main__":
    args = parser.parse_args()
    setLogLevel("info")
    main(args)

