import socket
import struct

ICMP6_DEST_UNREACH = 1
ICMP6_PKT_TOOBIG = 2
ICMP6_TIME_EXCEEDED = 3
ICMP6_PARAM_PROBLEM = 4
ICMP6_ECHO_REQ = 128
ICMP6_ECHO_REP = 129
ICMP6_ND_RS = 133
ICMP6_ND_RA = 134
ICMP6_ND_NS = 135
ICMP6_ND_NA = 136

SO_ICMP6_FILTER = 1


class ICMP6Filter:

    filter: list[int]

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

    def willpass(self, icmp6type: int) -> bool:
        return self.filter[icmp6type >> 5] & (1 << (icmp6type & 0x1f)) == 0

    def willblock(self, icmp6type: int) -> bool:
        return self.filter[icmp6type >> 5] & (1 << (icmp6type & 0x1f)) == 1

    def setsockopt(self, sock: socket.socket):
        sock.setsockopt(socket.IPPROTO_ICMPV6, SO_ICMP6_FILTER,
                        struct.pack('@8I', *self.filter))
