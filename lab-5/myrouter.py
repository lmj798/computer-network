#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

#cannot pass all tests

import time
from switchyard.lib.userlib import *
import switchyard

def insert_by_max(l: list, a):
    if len(l) == 0:
        l.append(a)
    else:
        c = 0
        for i in l:
            p1 = i[0].prefixlen
            p2 = a[0].prefixlen
            if p1 > p2:  # Use strict '>' comparison for correct order
                c += 1
            elif p1 == p2 and str(i[0]) < str(a[0]):  # Tie-breaker by network address if prefix lengths are equal
                c += 1
            else:
                break
        l.insert(c, a)

class Waiting_packet:
    def __init__(self, pkt, intf, dstip):
        self.packet = pkt
        self.last_send_time = time.time()  # Initialize time at packet creation
        self.count = 0
        self.router_intf = intf
        self.next_hop_ip = dstip


class Router(object):
    def __init__(self, net):
        self.net = net
        self.my_arptable = {}
        self.count_of_print = 0
        self.forwarding_table = []
        self.waiting_queue = []
        
        for intf in self.net.interfaces():
            ipad = IPv4Address(int(intf.ipaddr) & int(intf.netmask))
            x = IPv4Network(str(ipad)+'/'+str(intf.netmask))
            x1 = [x, '', intf.name]
            insert_by_max(self.forwarding_table, x1)

        try:
            with open("forwarding_table.txt", "r") as flies:
                a = flies.readlines()
            for i in range(len(a)):
                a[i] = a[i].split(" ")
                if i != len(a)-1:
                    a[i][3] = a[i][3].strip("\n")
            for i in a:
                x2 = [IPv4Network(i[0]+'/'+i[1]), i[2], i[3]]
                insert_by_max(self.forwarding_table, x2)
        except FileNotFoundError:
            print("666")

    def icmp_message(self, inter, pkt, dtype, icmp_code):
        packet = Ethernet() + IPv4() + ICMP()
        packet[1].dst = pkt[1].src
        packet[1].src = inter.ipaddr
        packet[1].ttl = 10
        packet[2].icmptype = dtype
        packet[2].icmpcode = icmp_code
        xpkt = deepcopy(pkt)
        i = xpkt.get_header_index(Ethernet)
        if i >= 0:
            del xpkt[i]
        packet[2].icmpdata.data = xpkt.to_bytes()[:28]
        packet[2].icmpdata.origdgramlen = len(xpkt)
        return packet

    def max_match(self, dst):
        fw_index = -1
        for i in range(len(self.forwarding_table)):
            if dst in self.forwarding_table[i][0]:
                fw_index = i
                break
        return fw_index

    def send_arp_request(self, router_intf, next_hop_ip):
        ether = Ethernet()
        ether.src = router_intf.ethaddr
        ether.dst = 'ff:ff:ff:ff:ff:ff'
        ether.ethertype = EtherType.ARP
        arp = Arp(operation=ArpOperation.Request,
                  senderhwaddr=router_intf.ethaddr,
                  senderprotoaddr=router_intf.ipaddr,
                  targethwaddr='ff:ff:ff:ff:ff:ff',
                  targetprotoaddr=str(next_hop_ip))  # Convert to string for ARP target IP
        arppacket = ether + arp
        self.net.send_packet(router_intf.name, arppacket)

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        timestamp, ifaceName, packet = recv
        arp = packet.get_header(Arp)
        ipv4 = packet.get_header(IPv4)
        
        if arp:
            self.my_arptable[arp.senderprotoaddr] = [arp.senderhwaddr, time.time()]
            if arp.operation == ArpOperation.Request:
                for intf in self.net.interfaces():
                    if intf.ipaddr == arp.targetprotoaddr:
                        response = create_ip_arp_reply(intf.ethaddr, arp.senderhwaddr, intf.ipaddr, arp.senderprotoaddr)
                        self.net.send_packet(ifaceName, response)
            for i in list(self.my_arptable.keys()):
                if time.time()-self.my_arptable[i][1] >= 100:
                    del self.my_arptable[i]
            log_info(f"ARPTABLE: {self.my_arptable}")
        
        elif ipv4:
            ipv4.ttl -= 1
            judging = True
            interface_macs = [intf.ethaddr for intf in self.net.interfaces()]
            ether = packet.get_header(Ethernet)
            
            if ether.dst != 'ff:ff:ff:ff:ff:ff' and ether.dst not in interface_macs:
                judging = False

            for intf in self.net.interfaces():
                if ipv4.dst == intf.ipaddr:
                    if packet.has_header(ICMP) and packet.get_header(ICMP).icmptype == ICMPType.EchoRequest:
                        icmp = packet.get_header(ICMP)
                        icmp_reply = ICMP()
                        icmp_reply.icmptype = ICMPType.EchoReply
                        icmp_reply.icmpdata.sequence = icmp.icmpdata.sequence
                        icmp_reply.icmpdata.identifier = icmp.icmpdata.identifier
                        icmp_reply.icmpdata.data = icmp.icmpdata.data
                        packet[1].dst = packet[1].src
                        packet[1].src = intf.ipaddr
                        packet[icmp.get_header_index()] = icmp_reply
                        break
                    else:
                        for intf1 in self.net.interfaces():
                            if intf1 == ifaceName:
                                inter = intf1
                                break
                        packet = self.icmp_message(inter, packet, ICMPType.DestinationUnreachable, 3)
                        break

            fw_index = self.max_match(ipv4.dst)
            if fw_index == -1:
                for intf in self.net.interfaces():
                    if intf.name == ifaceName:
                        inter = intf
                        break
                packet = self.icmp_message(inter, packet, ICMPType.DestinationUnreachable, 0)
                fw_index = self.max_match(packet[1].dst)
            
            packet[1].ttl -= 1
            if packet[1].ttl <= 0:
                for intf in self.net.interfaces():
                    if intf.name == ifaceName:
                        inter = intf
                        break
                packet = self.icmp_message(inter, packet, ICMPType.TimeExceeded, 0)
                fw_index = self.max_match(packet[1].dst)

            if self.forwarding_table[fw_index][1]:
                next_hop_ip = IPv4Address(self.forwarding_table[fw_index][1])
            else:
                next_hop_ip = packet[1].dst

            for intf in self.net.interfaces():
                if intf.name == self.forwarding_table[fw_index][2]:
                    router_intf = intf
                    break
            packet[0].src = router_intf.ethaddr
            self.waiting_queue.append(Waiting_packet(packet, router_intf, next_hop_ip))

    def start(self):
        '''A running daemon of the router.
        Receive packets until the end of time.
        '''
        while True:
            bb = True
            try:
                recv = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                bb = False
            except Shutdown:
                break
            if bb:
                self.handle_packet(recv)
            
            re = []
            without_query = []
            for i in self.waiting_queue:
                if i.next_hop_ip in self.my_arptable.keys():
                    mac = self.my_arptable[i.next_hop_ip][0]
                    i.packet[0].dst = str(mac)
                    self.net.send_packet(i.router_intf.name, i.packet)
                    without_query.append(i)
                elif time.time()-i.last_send_time >= 1 and i.next_hop_ip not in re:
                    if i.count < 5:
                        re.append(i.next_hop_ip)
                        self.send_arp_request(i.router_intf, i.next_hop_ip)
                        i.count += 1
                        i.last_send_time = time.time()
                    else:
                        nip = i.next_hop_ip
                        for j in self.waiting_queue:
                            if j.next_hop_ip == nip:
                                packet = self.icmp_message(j.router_intf, j.packet, ICMPType.DestinationUnreachable, 1)
                                f_index = self.max_match(packet[1].dst)
                                if self.forwarding_table[f_index][1]:
                                    next_hop_ip = IPv4Address(self.forwarding_table[f_index][1])
                                else:
                                    next_hop_ip = packet[1].dst
                                interface1 = self.forwarding_table[f_index][2]
                                for intf in self.net.interfaces():
                                    if intf.name == interface1:
                                        router_intf = intf
                                        break
                                packet[0].src = router_intf.ethaddr
                                packet[1].src = router_intf.ipaddr
                                self.waiting_queue.append(Waiting_packet(packet, router_intf, next_hop_ip))
                                without_query.append(j)
            for i in without_query:
                self.waiting_queue.remove(i)

        self.stop()

    def stop(self):
        self.net.shutdown()


def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    router = Router(net)
    router.start()