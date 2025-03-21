#!/usr/bin/env python3

import time
import threading
from random import randint
import random

import switchyard
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *


class Middlebox:
    def __init__(
            self,
            net: switchyard.llnetbase.LLNetBase,
            dropRate="0.19"
    ):
        self.net = net
        self.dropRate = float(dropRate)
        self.intf1 = "middlebox-eth0"
        

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        _, fromIface, packet = recv
        if fromIface == self.intf1:
            log_debug("Received from blaster")
            '''
            Received data packet
            Should I drop it?
            If not, modify headers & send to blastee
            '''
            r = random.random()
            if  r > self.dropRate:
                packet[Ethernet].src = '40:00:00:00:00:02'
                packet[Ethernet].dst = '20:00:00:00:00:01'
                self.net.send_packet("middlebox-eth1", packet)
                log_info("Receive data packet")
            else:
                log_info("Drop data packet")
        elif fromIface == "middlebox-eth1":
            log_debug("Received from blastee")
            '''
            Received ACK
            Modify headers & send to blaster. Not dropping ACK packets!
            net.send_packet("middlebox-eth0", pkt)
            '''
            packet[Ethernet].src = '40:00:00:00:00:01'
            packet[Ethernet].dst = '10:00:00:00:00:01'
            self.net.send_packet("middlebox-eth0", packet)
            log_info("Receive ACK")
        else:
            log_debug("Oops :))")

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

        self.shutdown()

    def shutdown(self):
        self.net.shutdown()


def main(net, **kwargs):
    middlebox = Middlebox(net, **kwargs)
    middlebox.start()
