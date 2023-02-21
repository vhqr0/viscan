import socket
import struct

from typing import List

ICMP6_ECHOREQ = 128
ICMP6_ECHOREP = 129
ICMP6ND_RS = 133
ICMP6ND_RA = 134
ICMP6ND_NS = 135
ICMP6ND_NA = 136

SO_ICMP6_FILTER = 1


class ICMP6Filter:

    filter: List[int]

    def __init__(self):
        self.filter = [0 for _ in range(8)]

    def setpassall(self):
        self.filter = [0 for _ in range(8)]

    def setblockall(self):
        self.filter = [0xffffffff for _ in range(8)]

    def setpass(self, icmp6type: int):
        self.filter[icmp6type >> 5] &= 0xffffffff - (1 << (icmp6type & 0x1f))

    def setblock(self, icmp6type: int):
        self.filter[icmp6type >> 5] |= 1 << (icmp6type & 0x1f)

    def willpass(self, icmp6type: int):
        return self.filter[icmp6type >> 5] & (1 << (icmp6type & 0x1f)) == 0

    def willblock(self, icmp6type: int):
        return self.filter[icmp6type >> 5] & (1 << (icmp6type & 0x1f)) == 1

    def setsockopt(self, sock: socket.socket):
        sock.setsockopt(socket.IPPROTO_ICMPV6, SO_ICMP6_FILTER,
                        struct.pack('@8I', *self.filter))
