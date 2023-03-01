import logging

from typing import Optional, Tuple, List, Dict

import scapy.layers.dhcp6 as dhcp6

from ...generic.base import FinalResultMixin
from ...utils.decorators import override
from ..base import DHCPBaseScanner, DHCPScanMixin
from ..scale import DHCPScaler


class DHCPLocator(FinalResultMixin[int], DHCPScanMixin, DHCPBaseScanner):
    scaler: DHCPScaler
    scales: Dict[str, Optional[Tuple[str, int, int, int]]]
    accept_ranges: Dict[str, Optional[Tuple[int, int]]]
    beg: int
    end: int
    mid: int

    # override DHCPBaseScanner
    logger = logging.getLogger('dhcp_scaler')
    # override DHCPScanMixin
    stateless = False

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        kwargs['sock'] = self.sock
        self.scaler = DHCPScaler(**kwargs)

    def accept(self, msg: dhcp6.DHCP6_Advertise) -> bool:
        na = self.get_na(msg)
        if na is not None:
            ar = self.accept_ranges['na']
            if ar is not None and \
               ar[0] <= na <= ar[1]:
                return True
        ta = self.get_ta(msg)
        if ta is not None:
            ar = self.accept_ranges['ta']
            if ar is not None and \
               ar[0] <= ta <= ar[1]:
                return True
        pd = self.get_pd(msg)
        if pd is not None:
            ar = self.accept_ranges['pd']
            if ar is not None and \
               ar[0] <= pd <= ar[1]:
                return True
        return False

    @override(DHCPScanMixin)
    def get_pkts(self) -> List[Tuple[str, int, bytes]]:
        buf = self.build_solicit()
        return [(self.target, 547, buf)]

    @override(DHCPScanMixin)
    def prepare_pkts(self) -> bool:
        if self.beg >= self.end:
            return False

        if self.pkts_prepared:
            for pkt in self.results:
                try:
                    _, _, buf = pkt
                    msg = self.parse_msg(buf)
                    if not isinstance(msg, dhcp6.DHCP6_Advertise):
                        continue
                    if self.accept(msg):
                        self.end = self.mid
                        break
                except Exception:
                    pass
            else:
                self.beg = self.mid + 1
            self.mid = (self.beg + self.end) // 2

        self.pkts_prepared = False
        super().prepare_pkts()

    @override(DHCPScanMixin)
    def init_scan(self):
        self.scaler.run()
        self.scaler.parse()
        self.scales = self.scaler.final_result
        self.accept_ranges = self.scaler.get_accept_ranges()
        if self.scales['na'] is None and \
           self.scales['ta'] is None and \
           self.scales['pd'] is None:
            raise RuntimeError('stateless dhcp detected')
        self.beg = 0
        self.end = 128
        self.mid = 64
        super().init_scan()
