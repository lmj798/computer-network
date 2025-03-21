#!/usr/bin/env python3

import time
import threading
from struct import pack
import switchyard
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *


class Blastee:
    def __init__(
            self,
            net: switchyard.llnetbase.LLNetBase,
            blasterIp,
            num
    ):
        self.net = net
        # TODO: store the parameters
        self.num = int(num)
        self.blasterIp = IPv4Address(blasterIp)

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        _, fromIface, packet = recv
        log_debug(f"I got a packet from {fromIface}")
        log_debug(f"Pkt: {packet}")

        eth_header = Ethernet(src="20:00:00:00:00:01", dst="40:00:00:00:00:02", ethertype=EtherType.IP)
        ipv4_header = IPv4(protocol=IPProtocol.UDP, src=IPv4Address('192.168.200.1'), dst=self.blasterIp)
        udp_header = UDP(src=12345, dst=54321)
        ack = eth_header + ipv4_header + udp_header
        payload_len = int.from_bytes(packet[3].to_bytes()[4:6], "big")
        if payload_len >= 8:
            ack = ack + packet[3].to_bytes()[:4] + packet[3].to_bytes()[6:14]
        else:
            ack = ack + packet[3].to_bytes()[:4] + packet[3].to_bytes()[6:] + (0).to_bytes(8 - payload_len, "big")
        self.net.send_packet(fromIface, ack)
        log_info(f"send ack: {ack}")


    def start(self):
        '''A running daemon of the blastee.
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
    blastee = Blastee(net, **kwargs)
    blastee.start()
