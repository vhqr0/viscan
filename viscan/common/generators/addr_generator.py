import random
import re
import socket
import ipaddress

from ...defaults import MAX_TARGETS


class AddrGenerator:
    addrs: set[str]
    skip_check_max_targets: bool

    subnet_addrs_re = re.compile(r'^(.*)/(\d+)$')
    range_addrs_re = re.compile(r'^(.*)-(.*)$')

    def __init__(self, addrs: list[str], skip_check_max_targets: bool = False):
        self.addrs = set()
        self.skip_check_max_targets = skip_check_max_targets
        for addr in addrs:
            if self.try_add_subnet_addrs(addr) or \
               self.try_add_range_addrs(addr) or \
               self.try_add_single_addr(addr):
                continue
            raise ValueError(f'invalid addr str: {addr}')

    @staticmethod
    def resolve(addr):
        info = socket.getaddrinfo(host=addr,
                                  port=0,
                                  family=socket.AF_INET6,
                                  type=socket.SOCK_DGRAM)
        return random.choice(info)[-1][0]

    def add_addr(self, addr: str):
        self.addrs.add(addr)
        if not self.skip_check_max_targets and len(self.addrs) > MAX_TARGETS:
            raise ValueError('too many addrs')

    def try_add_subnet_addrs(self, addr_str: str) -> bool:
        res = self.subnet_addrs_re.match(addr_str)
        if res is None:
            return False
        addr, diff = self.resolve(res[1]), int(res[2])
        network = ipaddress.IPv6Network(f'{addr}/{diff}', strict=False)
        for addr in network:
            self.add_addr(str(addr))
        return True

    def try_add_range_addrs(self, addr_str: str) -> bool:
        res = self.range_addrs_re.match(addr_str)
        if res is None:
            return False
        addr1, addr2 = self.resolve(res[1]), self.resolve(res[2])
        a1 = int(ipaddress.IPv6Address(addr1))
        a2 = int(ipaddress.IPv6Address(addr2))
        if a1 >= a2:
            raise ValueError(f'invalid range addrs: {addr1}-{addr2}')
        for a in range(a1, a2):
            self.add_addr(str(ipaddress.IPv6Address(a)))
        return True

    def try_add_single_addr(self, addr_str: str) -> bool:
        addr = self.resolve(addr_str)
        self.add_addr(addr)
        return True
