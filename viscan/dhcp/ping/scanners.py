import base64
import logging

from typing import Optional, Dict, Tuple, List

import scapy.all as sp
import scapy.layers.dhcp6 as dhcp6

from ...generic.base import FinalResultMixin
from ...utils.decorators import override
from ..base import DHCPScanMixin, DHCPBaseScanner


class DHCPPinger(FinalResultMixin[Tuple[Optional[dhcp6.DHCP6_Reply],
                                        Optional[dhcp6.DHCP6_Advertise]]],
                 DHCPScanMixin, DHCPBaseScanner):
    dhcp_reply: Optional[dhcp6.DHCP6_Reply]
    dhcp_advertise: Optional[dhcp6.DHCP6_Advertise]

    # override DHCPBaseScanner
    logger = logging.getLogger('dhcp_pinger')
    # override DHCPScanMixin
    stateless = False

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    @override(DHCPScanMixin)
    def get_pkts(self) -> List[Tuple[str, int, bytes]]:
        buf1 = self.build_inforeq(trid=1)
        buf2 = self.build_solicit(trid=2)
        return [(self.target, 547, buf1), (self.target, 547, buf2)]

    @override(DHCPScanMixin)
    def send_pkts_stop_retry(self) -> bool:
        for pkt in self.results:
            _, _, buf = pkt
            try:
                msg = self.parse_msg(buf)
                if isinstance(msg, dhcp6.DHCP6_Reply):
                    if msg.trid != 1 or dhcp6.DHCP6OptServerId not in msg:
                        raise ValueError('invaid reply')
                    if self.dhcp_reply is not None:
                        raise ValueError('duplicated reply')
                    self.dhcp_reply = msg
                if isinstance(msg, dhcp6.DHCP6_Advertise):
                    if msg.trid != 2 or dhcp6.DHCP6OptServerId not in msg:
                        raise ValueError('invalid advertise')
                    if self.dhcp_advertise is not None:
                        raise ValueError('duplicated advertise')
                    self.dhcp_advertise = msg
            except Exception as e:
                self.logger.debug('except while parsing: %s', e)
                continue
        self.results.clear()
        return self.dhcp_reply is not None and \
            self.dhcp_advertise is not None

    @override(DHCPScanMixin)
    def init_send_loop(self):
        self.dhcp_reply = None
        self.dhcp_advertise = None
        super().init_send_loop()

    @override(FinalResultMixin)
    def parse(self):
        self.final_result = (self.dhcp_reply, self.dhcp_advertise)

    @override(FinalResultMixin)
    def print(self):
        for name, pkt in zip(('reply', 'advertise'), self.final_result):
            print(f'name: {name}')
            if pkt is None:
                print(None)
            else:
                pkt.show()

    @override(FinalResultMixin)
    def to_jsonable(self) -> Dict[str, Optional[str]]:
        results: Dict[str, Optional[str]] = dict()
        for name, pkt in zip(('reply', 'advertise'), self.final_result):
            if pkt is None:
                results[name] = None
            else:
                results[name] = base64.b64encode(sp.raw(pkt)).decode()
        return results
