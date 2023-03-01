import ipaddress
import logging

import scapy.layers.dhcp6 as dhcp6

from typing import Optional, Tuple, List, Dict

from ...generic.base import FinalResultMixin
from ...utils.decorators import override
from ..base import DHCPBaseScanner, DHCPScanMixin
from .algos import scale, accept_range


class DHCPScaler(FinalResultMixin[Dict[str, Optional[Tuple[str, int, int,
                                                           int]]]],
                 DHCPScanMixin, DHCPBaseScanner):
    count: int
    lossrate: float

    # override DHCPBaseScanner
    logger = logging.getLogger('dhcp_scaler')

    @override(DHCPScanMixin)
    def get_pkts(self) -> List[Tuple[str, int, bytes]]:
        pkts = []
        for trid in range(self.count):
            buf = self.build_solicit(trid=trid)
            pkts.append((self.target, 547, buf))
        return pkts

    @override(FinalResultMixin)
    def parse(self):
        na_addrs: List[Optional[str]] = [None for _ in range(self.count)]
        ta_addrs: List[Optional[str]] = [None for _ in range(self.count)]
        pd_addrs: List[Optional[str]] = [None for _ in range(self.count)]
        for pkt in self.results:
            _, _, buf = pkt
            msg = self.parse_msg(buf)
            if not isinstance(msg, dhcp6.DHCP6_Advertise):
                continue
            trid = msg.trid
            if trid >= self.count:
                continue
            na_addrs.append(self.get_na(msg))
            ta_addrs.append(self.get_ta(msg))
            pd_addrs.append(self.get_pd(msg))

        results: Dict[str, Optional[Tuple[str, int, int, int]]] = dict()
        for name, addrs in zip(('na', 'ta', 'pd'),
                               (na_addrs, ta_addrs, pd_addrs)):
            addrs = [addr for addr in addrs if addr is not None]
            if len(addrs) < self.lossrate * self.count:
                results[name] = None
            else:
                results[name] = scale(
                    [int(ipaddress.IPv6Address(addr)) for addr in addrs])

        self.final_result = results

    @override(FinalResultMixin)
    def print(self):
        for name, args in self.final_result.items():
            if args is None:
                print(f'{name}:\tNone')
            else:
                t, a1, a2, d = args
                print(f'{name} t:\t{t}')
                print(f'{name} a1:\t{ipaddress.IPv6Address(a1)}')
                print(f'{name} a2:\t{ipaddress.IPv6Address(a2)}')
                print(f'{name} d:\t{ipaddress.IPv6Address(d)}')

    @override(FinalResultMixin)
    def to_jsonable(self) -> Dict[str, Optional[Dict[str, str]]]:
        results: Dict[str, Optional[Dict[str, str]]] = dict()
        for name, args in self.final_result.items():
            if args is None:
                results[name] = None
            else:
                t, a1, a2, d = args
                results[name] = {
                    't': t,
                    'a1': str(ipaddress.IPv6Address(a1)),
                    'a2': str(ipaddress.IPv6Address(a2)),
                    'd': str(ipaddress.IPv6Address(d)),
                }
        return results

    def get_accept_ranges(self) -> Dict[str, Optional[Tuple[int, int]]]:
        results: Dict[str, Optional[Tuple[int, int]]] = dict()
        for name, args in self.final_result.items():
            if args is None:
                results[name] = None
            else:
                t, a1, a2, d = args
                results[name] = accept_range(t, a1, a2, d)
        return results