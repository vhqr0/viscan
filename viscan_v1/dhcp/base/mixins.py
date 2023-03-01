import random

import scapy.all as sp
import scapy.layers.dhcp6 as dhcp6

from typing import Any, Optional, Tuple, Dict
from argparse import Namespace

from ...defaults import (
    DHCP_LOCATE_STEP,
    DHCP_SCALE_COUNT,
    DHCP_SCALE_LOSSRATE,
)
from ...generic.base import GenericMainMixin
from ...generic.dgram import DgramScanMixin, UDPSockMixin
from ...utils.decorators import override
from ...utils.argparser import GenericScanArgParser
from ...utils.generators import AddrGenerator
from .scanners import MixinForDHCPBaseScanner


class DHCPScanMixin(GenericMainMixin, UDPSockMixin, DgramScanMixin,
                    MixinForDHCPBaseScanner):
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

    def get_na(self, msg: dhcp6.DHCP6) -> Optional[str]:
        if dhcp6.DHCP6OptIA_NA in msg:
            opts = msg[dhcp6.DHCP6OptIA_NA].ianaopts
            for opt in opts:
                if isinstance(opt, dhcp6.DHCP6OptIAAddress):
                    return opt.addr
        return None

    def get_ta(self, msg: dhcp6.DHCP6) -> Optional[str]:
        if dhcp6.DHCP6OptIA_TA in msg:
            opts = msg[dhcp6.DHCP6OptIA_TA].iataopts
            for opt in opts:
                if isinstance(opt, dhcp6.DHCP6OptIAAddress):
                    return opt.addr
        return None

    def get_pd(self, msg: dhcp6.DHCP6) -> Optional[str]:
        if dhcp6.DHCP6OptIA_PD in msg:
            opts = msg[dhcp6.DHCP6OptIA_PD].iapdopt  # it's iapdopt :-)
            for opt in opts:
                if isinstance(opt, dhcp6.DHCP6OptIAPrefix):
                    return opt.prefix
        return None

    @override(DgramScanMixin)
    def lfilter(self, result: Tuple[str, int, bytes]) -> bool:
        addr, port, buf = result
        return addr == self.target and port == 547

    @classmethod
    @override(GenericMainMixin)
    def get_argparser(cls, *args, **kwargs) -> GenericScanArgParser:
        parser = super().get_argparser(*args, **kwargs)
        parser.add_step_dwim(DHCP_LOCATE_STEP)
        parser.add_count_dwim(DHCP_SCALE_COUNT)
        parser.add_lossrate_dwim(DHCP_SCALE_LOSSRATE)
        return parser

    @classmethod
    @override(GenericMainMixin)
    def add_scan_kwargs(cls, raw_args: Namespace, scan_kwargs: Dict[str, Any]):
        super().add_scan_kwargs(raw_args, scan_kwargs)
        scan_kwargs['step'] = raw_args.step_dwim
        scan_kwargs['count'] = raw_args.count_dwim
        scan_kwargs['lossrate'] = raw_args.lossrate_dwim
        scan_kwargs['target'] = AddrGenerator.resolve(raw_args.targets[0])
