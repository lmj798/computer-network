'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
import switchyard
from switchyard.lib.userlib import *
import time


def main(net: switchyard.llnetbase.LLNetBase):
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]
    table = {}

    while True:
        try:
            _, fromIface, packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            break

        log_debug (f"In {net.name} received packet {packet} on {fromIface}")
        eth = packet.get_header(Ethernet)
        if eth is None:
            log_info("Received a non-Ethernet packet?!")
            return
        else:
            table[eth.src] = (fromIface, time.time())
        for mac in list(table.keys()):
            if time.time()-table[mac][1] >= 10:
                del table[mac]
        if eth.dst in mymacs:
            log_info("Received a packet intended for me")
        else:
            if eth.dst in table:
                net.send_packet(table[eth.dst][0], packet)
            else:
                for intf in my_interfaces:
                        if fromIface!= intf.name:
                            log_info (f"Flooding packet {packet} to {intf.name}")
                            net.send_packet(intf, packet)

    net.shutdown()
