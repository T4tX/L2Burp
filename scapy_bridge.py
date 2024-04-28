#!/usr/bin/python2

"""
Use scapy to modify packets going through your machine.
Based on netfilterqueue to block packets in the kernel and pass them to scapy for validation
"""

from netfilterqueue import NetfilterQueue as nfqueue
from scapy.all import *
import os

# All packets that should be filtered :

# If you want to use it as a reverse proxy for your machine
# iptablesr = "iptables -A OUTPUT -j NFQUEUE --queue-num 0"

# If you want to use it for MITM :
# iptablesr = "iptables -A FORWARD -j NFQUEUE --queue-num 0"

# print("Adding iptable rules :")
# print(iptablesr)
# os.system(iptablesr)

def callback(pkt):
    # Here is where the magic happens.
    try:
        # Get packet data and convert it to scapy packet
        print(pkt.command())
        # data = pkt.get_payload()
        # pkt = IP(data)
        print("Got a packet ! source ip : " + str(pkt.src))
        # Drop all packets coming from this IP
        # print("Dropped it. Oops")
        # pkt.drop()
        # Let the rest go it's way
        # pkt.accept()
    except Exception as e:
        print(e)
        # pkt.accept()

def main():
    # This is the intercept
    q = nfqueue()
    q.bind(0, callback)
    q.run()

if __name__ == "__main__":
    main()