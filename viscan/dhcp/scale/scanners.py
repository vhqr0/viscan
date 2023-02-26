import ipaddress
import logging

import scapy.layers.dhcp6 as dhcp6

from typing import Any, Optional, Tuple, List, Dict
from argparse import Namespace

from ...defaults import (
    DHCP_SCALE_COUNT,
    DHCP_SCALE_LOSSRATE,
)
from ...generic.base import FinalResultMixin, GenericMainMixin
from ...utils.decorators import override
from ...utils.argparser import GenericScanArgParser
from ...utils.generators import AddrGenerator
from ..base import DHCPScanMixin, DHCPBaseScanner
from .algos import scale, accept_range


class DHCPScaler(GenericMainMixin,
                 FinalResultMixin[Dict[str, Optional[Tuple[str, int, int,
                                                           int]]]],
                 DHCPScanMixin, DHCPBaseScanner):
    count: int
    lossrate: float

    # override DHCPBaseScanner
    logger = logging.getLogger('dhcp_scaler')

    def __init__(self,
                 count: int = DHCP_SCALE_COUNT,
                 lossrate: float = DHCP_SCALE_LOSSRATE,
                 **kwargs):
        self.count = count
        self.lossrate = lossrate
        super().__init__(**kwargs)

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
            print(f'name: {name}')
            if args is None:
                print(None)
            else:
                t, a1, a2, d = args
                print(f't: {t}')
                print(f'a1: {ipaddress.IPv6Address(a1)}')
                print(f'a2: {ipaddress.IPv6Address(a2)}')
                print(f'd: {ipaddress.IPv6Address(d)}')

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

    def get_accept_range(self) -> Dict[str, Optional[Tuple[int, int]]]:
        results: Dict[str, Optional[Tuple[int, int]]] = dict()
        for name, args in self.final_result.items():
            if args is None:
                results[name] = None
            else:
                t, a1, a2, d = args
                results[name] = accept_range(t, a1, a2, d)
        return results

    @classmethod
    @override(GenericMainMixin)
    def get_argparser(cls, *args, **kwargs) -> GenericScanArgParser:
        parser = super().get_argparser(*args, **kwargs)
        parser.add_count_dwim(DHCP_SCALE_COUNT)
        parser.add_lossrate_dwim(DHCP_SCALE_LOSSRATE)
        return parser

    @classmethod
    @override(GenericMainMixin)
    def add_scan_kwargs(cls, raw_args: Namespace, scan_kwargs: Dict[str, Any]):
        super().add_scan_kwargs(raw_args, scan_kwargs)
        scan_kwargs['count'] = raw_args.count_dwim
        scan_kwargs['lossrate'] = raw_args.lossrate_dwim
        scan_kwargs['target'] = AddrGenerator.resolve(raw_args.targets[0])
