import base64
import logging

from typing import Optional, Dict, Tuple, List

import scapy.all as sp
import scapy.layers.dhcp6 as dhcp6

from ...utils.decorators import override
from ..base import DHCPScanMixin, DHCPBaseScanner


class DHCPPinger(DHCPScanMixin, DHCPBaseScanner):
    dhcp_reply: Optional[dhcp6.DHCP6_Reply]
    dhcp_advertise: Optional[dhcp6.DHCP6_Advertise]

    # override DHCPBaseScanner
    logger = logging.getLogger('dhcp_pinger')
    # override DHCPScanMixin
    stateless = False

    def __init__(self, **kwargs):
        self.dhcp_reply = None
        self.dhcp_advertise = None
        super().__init__(**kwargs)

    def parse(self) -> Dict[str, Optional[str]]:
        results: Dict[str, Optional[str]] = {'addr': self.target}
        for name, msg in [('inforeq', self.dhcp_reply),
                          ('solicit', self.dhcp_advertise)]:
            if msg is None:
                results[name] = None
            else:
                results[name] = base64.b64encode(sp.raw(msg)).decode()
        return results

    @override(DHCPScanMixin)
    def get_pkts(self) -> List[Tuple[str, int, bytes]]:
        buf1 = self.build_inforeq(trid=1)
        buf2 = self.build_solicit(trid=2)
        return [(self.target, 547, buf1), (self.target, 547, buf2)]

    @override(DHCPScanMixin)
    def send_pkts_stop_retry(self) -> bool:
        for pkt in self.results:
            addr, port, buf = pkt
            if addr != self.target and port != 547:
                continue
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
