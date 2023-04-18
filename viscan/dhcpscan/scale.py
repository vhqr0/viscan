import math
import ipaddress
import functools

import scapy.layers.dhcp6 as dhcp6

from typing_extensions import Self
from typing import Any, Optional

from ..common.base import ResultParser
from ..common.decorators import override
from .base import DHCPBaseScanner


class DHCPPoolScale:
    t: str
    a1: int
    a2: int
    d: int

    def __init__(self, t: str, a1: int, a2: int, d: int):
        self.t = t
        self.a1 = a1
        self.a2 = a2
        self.d = d

    @classmethod
    def from_strs(cls, addrs: list[str]) -> Self:
        return cls.from_ints(
            [int(ipaddress.IPv6Address(addr)) for addr in addrs])

    @classmethod
    def from_ints(cls, addrs: list[int]) -> Self:
        diffs = [addrs[i + 1] - addrs[i] for i in range(len(addrs) - 1)]
        zeros = [d for d in diffs if d == 0]
        poses = [d for d in diffs if d > 0]
        negs = [d for d in diffs if d < 0]

        if len(zeros) == len(diffs):
            return cls('static', addrs[0], addrs[-1], 0)

        if len(poses) >= 0.9 * len(diffs):
            avg = sum(poses) / len(poses)
            if len(negs) == 0 or abs(min(negs)) < 2 * avg:
                return cls('linear', addrs[0], addrs[-1], math.ceil(avg))

        if len(negs) >= 0.9 * len(diffs):
            avg = sum(negs) / len(negs)
            if len(poses) == 0 or max(poses) < 2 * abs(avg):
                return cls('linear', addrs[0], addrs[-1], math.ceil(avg))

        a1, a2 = min(addrs), max(addrs)
        d = math.ceil((a2 - a1) / (len(addrs) - 1))
        return cls('random', a1, a2, d)

    @functools.cached_property
    def accept_range(self):
        if self.t == 'static':
            return (self.a1, self.a2)
        if self.t == 'linear':
            if self.d > 0:
                return (self.a2, self.a2 + 128 * self.d)
            else:
                return (self.a1 + 128 * self.d, self.a1)
        return self.a1 - 2 * self.d, self.a2 + 2 * self.d

    def __contains__(self, addr: str) -> bool:
        a, b = self.accept_range
        return a <= int(ipaddress.IPv6Address(addr)) <= b

    def get_jsonable(self) -> dict[str, Any]:
        return {
            't': self.t,
            'a1': str(ipaddress.IPv6Address(self.a1)),
            'a2': str(ipaddress.IPv6Address(self.a2)),
            'd': str(ipaddress.IPv6Address(self.d)),
        }

    def summary(self) -> str:
        return '\t'.join(self.get_jsonable().values())


class DHCPScaler(ResultParser[dict[str, Optional[DHCPPoolScale]]],
                 DHCPBaseScanner):

    @override(ResultParser)
    def parse(self):
        na_addrs: list[Optional[str]] = [None for _ in range(self.count)]
        ta_addrs: list[Optional[str]] = [None for _ in range(self.count)]
        pd_addrs: list[Optional[str]] = [None for _ in range(self.count)]

        for pkt in self.recv_pkts:
            _, _, buf = pkt
            try:
                msg = self.parse_msg(buf)
                if not isinstance(msg, dhcp6.DHCP6_Advertise):
                    continue
                trid = msg.trid
                if trid >= self.count:
                    continue
                na_addrs.append(self.get_na(msg))
                ta_addrs.append(self.get_ta(msg))
                pd_addrs.append(self.get_pd(msg))
            except Exception as e:
                self.logger.debug('except while parsing: %s', e)

        results: dict[str, Any] = dict()
        for name, addrs in zip(('na', 'ta', 'pd'),
                               (na_addrs, ta_addrs, pd_addrs)):
            addr_strs: list[str] = [addr for addr in addrs if addr is not None]
            if len(addr_strs) < self.lossrate * self.count:
                results[name] = None
            else:
                results[name] = DHCPPoolScale.from_strs(addr_strs)
        self.result = results

    @override(ResultParser)
    def get_jsonable(self) -> dict[str, Any]:
        assert self.result is not None
        results: dict[str, Any] = dict()
        for name, scale in self.result.items():
            if scale is None:
                results[name] = None
            else:
                results[name] = scale.get_jsonable()
        return results

    @override(ResultParser)
    def show(self):
        assert self.result is not None
        for name, scale in self.result.items():
            if scale is not None:
                print(f'{name}\t{scale.summary()}')

    @override(DHCPBaseScanner)
    def get_pkts(self) -> list[tuple[str, int, bytes]]:
        pkts = []
        for trid in range(self.count):
            buf = self.build_solicit(trid=trid)
            pkts.append((self.target, 547, buf))
        return pkts

    @override(DHCPBaseScanner)
    def send(self):
        self.send_pkts_with_timewait()


if __name__ == '__main__':
    DHCPScaler.main()
