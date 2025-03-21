#!/usr/bin/env python3

import time
from random import randint
import switchyard
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *

class Blaster:
    def __init__(self,net: switchyard.llnetbase.LLNetBase,blasteeIp, num,  length="100",senderWindow="5", timeout="3",recvTimeout="1"):
        self.net = net
        self.blasteeIp = blasteeIp
        self.num = int(num)
        self.length = int(length)
        self.senderWindow = int(senderWindow)
        self.timeout = float(timeout)/1000
        self.recvTimeout = float(recvTimeout)/1000

        self.LHS=1
        self.RHS=self.LHS+self.senderWindow-1
        self.time=time.time()
        self.acks=[False for i in range(self.num+1)]
        self.payloads=[0 for i in range(self.num+1)]

        self.transmit_seq = []
        self.first_send_time = 0
        self.last_update_time = 0
        self.FirstSend=[True for i in range(self.num+1)]
        self.retransmit_count = 0
        self.number_of_coarse_TOs = 0
        self.throughput=0
        self.goodput=0
        self.count_of_send = 0

        for i in range(1,self.num+1):
            self.payloads[i]=randint(0,2**32-1).to_bytes(self.length,'big')


    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        _, fromIface, packet = recv
        self.time=time.time()
        seq = int.from_bytes(packet[3].to_bytes()[:4], 'big')
        log_info(f"got a ACK packet with ACKnum: {seq}")

        if seq in self.transmit_seq:
            self.transmit_seq.remove(seq)

        self.acks[seq]=True

        while self.acks[self.LHS] and self.LHS<=self.RHS: 
            self.LHS+=1
            if self.LHS==self.num+1:
                break


        while self.RHS<self.num and self.RHS-self.LHS+1 < self.senderWindow:
            self.RHS+=1
            self.transmit_seq.append(self.RHS)
        
        if self.LHS==self.num+1:
            log_info("All packets have been sent")
            self.shutdown()

    def handle_no_packet(self):
        if time.time()-self.time>self.timeout: 
            self.number_of_coarse_TOs += 1
            self.time = time.time()
            for i in range(self.LHS,self.RHS+1):
                if not self.acks[i]:
                    self.transmit_seq.append(i)
            self.transmit_single_packet()
        else:
            self.transmit_single_packet()


    def transmit_single_packet(self):
        if len(self.transmit_seq) != 0:
            current_num = self.transmit_seq.pop(0)
            SequencePart = RawPacketContents(current_num.to_bytes(4,'big')+self.length.to_bytes(2,'big'))
            Payload = RawPacketContents(self.payloads[current_num])
            eth_header = Ethernet(src="10:00:00:00:00:01", dst="40:00:00:00:00:01")
            ipv4_header = IPv4(protocol=IPProtocol.UDP, src='192.168.100.1', dst=self.blasteeIp)
            udp_header = UDP(src=12345, dst=54321)
            pkt = eth_header+ipv4_header+udp_header+SequencePart+Payload
            seq_num = int.from_bytes(SequencePart.to_bytes()[:4],'big')
            log_info(f"sending the packet:{seq_num}")
            self.net.send_packet('blaster-eth0',pkt)

            self.count_of_send += 1
            if self.count_of_send == 1:
                self.first_send_time = time.time()

            if self.FirstSend[current_num] == True:
                self.goodput += len(Payload)
                self.FirstSend[current_num] = False
            else:
                self.retransmit_count += 1
            self.throughput += len(Payload)
            return

    def start(self):
        '''
        A running daemon of the blaster.
        Receive packets until the end of time.
        '''
        while True:
            try:
                recv = self.net.recv_packet(timeout=self.recvTimeout)
                self.last_update_time = time.time()
            except NoPackets:
                self.handle_no_packet()
                continue
            except Shutdown:
                break

            self.handle_packet(recv)

        log_info(" ")
        total_TX_time=self.last_update_time-self.first_send_time
        log_info(f'total TX time: {total_TX_time}s')
        log_info(f'number of reTX: {self.retransmit_count}')
        log_info(f'number of coarse TOs: {self.number_of_coarse_TOs}')
        log_info(f'throughput: {self.throughput/total_TX_time}')
        log_info(f'goodput: {self.goodput/total_TX_time}')
        self.shutdown()

    def shutdown(self):
        self.net.shutdown()


def main(net, **kwargs):
    blaster = Blaster(net, **kwargs)
    blaster.start()