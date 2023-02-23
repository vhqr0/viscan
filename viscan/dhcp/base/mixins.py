import random

import scapy.all as sp
import scapy.layers.dhcp6 as dhcp6

from typing import Optional

from ...generic.dgram import DgramScanMixin, UDPSockMixin
from .scanners import MixinForDHCPBaseScanner


class DHCPScanMixin(UDPSockMixin, DgramScanMixin, MixinForDHCPBaseScanner):
    # override UDPSockMixin
    udp_addr = ('::', 547)

    def build_inforeq(self,
                      linkaddr: Optional[str] = None,
                      trid: Optional[int] = None) -> bytes:
        linkaddr = linkaddr if linkaddr is not None else self.target
        trid = trid if trid is not None else random.getrandbits(16)
        msg = dhcp6.DHCP6_InfoRequest(trid=trid) / \
            dhcp6.DHCP6OptClientId(duid=self.duid) / \
            dhcp6.DHCP6OptOptReq()
        pkt = dhcp6.DHCP6_RelayForward(linkaddr=linkaddr) / \
            dhcp6.DHCP6OptRelayMsg(message=msg)
        return sp.raw(pkt)

    def build_solicit(self,
                      linkaddr: Optional[str] = None,
                      trid: Optional[int] = None) -> bytes:
        linkaddr = linkaddr if linkaddr is not None else self.target
        trid = trid if trid is not None else random.getrandbits(16)
        msg = dhcp6.DHCP6_Solicit(trid=trid) / \
            dhcp6.DHCP6OptClientId(duid=self.duid) / \
            dhcp6.DHCP6OptOptReq() / \
            dhcp6.DHCP6OptElapsedTime() / \
            dhcp6.DHCP6OptIA_NA(iaid=random.getrandbits(32)) / \
            dhcp6.DHCP6OptIA_TA(iaid=random.getrandbits(32)) / \
            dhcp6.DHCP6OptIA_PD(iaid=random.getrandbits(32))
        pkt = dhcp6.DHCP6_RelayForward(linkaddr=linkaddr) / \
            dhcp6.DHCP6OptRelayMsg(message=msg)
        return sp.raw(pkt)

    def parse_msg(self, buf: bytes) -> dhcp6.DHCP6:
        pkt = dhcp6._dhcp6_dispatcher(buf)
        if not isinstance(pkt, dhcp6.DHCP6_RelayReply) or \
           dhcp6.DHCP6OptRelayMsg not in pkt:
            raise ValueError('invalid relay reply')
        return pkt[dhcp6.DHCP6OptRelayMsg].message
