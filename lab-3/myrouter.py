#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import time
import switchyard
from switchyard.lib.userlib import *


class Router(object):
    def __init__(self, net: switchyard.llnetbase.LLNetBase):
        self.net = net
        self.my_arptable = {}
        self.count_of_print = 0
        # other initialization stuff here

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        timestamp, ifaceName, packet = recv
        # TODO: your logic here
        arp = packet.get_header(Arp)
        if arp:
            cc = 0
            for intf in self.net.interfaces():
                if intf.ipaddr == arp.targetprotoaddr:
                    cc = 1
                    response = create_ip_arp_reply(intf.ethaddr, arp.senderhwaddr, intf.ipaddr, arp.senderprotoaddr)
                    self.net.send_packet(ifaceName, response)
            if cc == 1:
                self.my_arptable[arp.senderprotoaddr] = [arp.senderhwaddr,time.time()]
                for i in list(self.my_arptable.keys()):
                    if time.time()-self.my_arptable[i][1] >= 100:
                        del self.my_arptable[i]
                log_info(str(self.count_of_print))
                for i in list(self.my_arptable.keys()):
                    log_info(str(self.my_arptable))


    def start(self):
        '''A running daemon of the router.
        Receive packets until the end of time.
        '''
        while True:
            try:
                recv = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                continue
            except Shutdown:
                break

            self.handle_packet(recv)

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
