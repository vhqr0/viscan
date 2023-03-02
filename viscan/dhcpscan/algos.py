import math
import ipaddress

from typing_extensions import Self
from typing import Any


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

    def get_accept_range(self):
        if self.t == 'static':
            return (self.a1, self.a2)
        if self.t == 'linear':
            if self.d > 0:
                return (self.a2, self.a2 + 128 * self.d)
            else:
                return (self.a1 + 128 * self.d, self.a1)
        return self.a1 - 2 * self.d, self.a2 + 2 * self.d

    def get_jsonable(self) -> dict[str, Any]:
        return {
            't': self.t,
            'a1': str(ipaddress.IPv6Address(self.a1)),
            'a2': str(ipaddress.IPv6Address(self.a2)),
            'd': str(ipaddress.IPv6Address(self.d)),
        }

    def show(self):
        for k, v in self.get_jsonable().items():
            print(f'{k}:\t{v}')
