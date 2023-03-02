import random
import logging

import scapy.layers.dhcp6 as dhcp6

from typing import Any, Optional
from argparse import Namespace

from ..defaults import (
    DHCP_LOCATE_STEP,
    DHCP_SCALE_COUNT,
    DHCP_SCALE_LOSSRATE,
)
from ..common.base import ResultParser, MainRunner
from ..common.dgram import UDPScanner
from ..common.decorators import override
from ..common.argparser import ScanArgParser
from ..common.generators import AddrGenerator


class DHCPBaseScanner(UDPScanner, MainRunner):
    target: str
    step: int
    count: int
    lossrate: float
    duid: dhcp6.DUID_LL

    udp_addr = ('::', 547)

    def __init__(self,
                 target: str,
                 step: int = DHCP_LOCATE_STEP,
                 count: int = DHCP_SCALE_COUNT,
                 lossrate: float = DHCP_SCALE_LOSSRATE,
                 **kwargs):
        super().__init__(**kwargs)
        self.target = target
        self.step = step
        self.count = count
        self.lossrate = lossrate
        self.duid = dhcp6.DUID_LL(lladdr=random.randbytes(6))

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
        return bytes(pkt)

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
        return bytes(pkt)

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

    @override(UDPScanner)
    def recv_filter(self, result: tuple[str, int, bytes]) -> bool:
        addr, port, buf = result
        return addr == self.target and port == 547

    @classmethod
    @override(MainRunner)
    def get_argparser(cls, *args, **kwargs) -> ScanArgParser:
        parser = super().get_argparser(*args, **kwargs)
        parser.add_step_dwim(DHCP_LOCATE_STEP)
        parser.add_count_dwim(DHCP_SCALE_COUNT)
        parser.add_lossrate_dwim(DHCP_SCALE_LOSSRATE)
        return parser

    @classmethod
    @override(MainRunner)
    def parse_args(cls, args: Namespace) -> dict[str, Any]:
        kwargs = super().parse_args(args)
        kwargs['step'] = args.step_dwim
        kwargs['count'] = args.count_dwim
        kwargs['lossrate'] = args.lossrate_dwim
        kwargs['target'] = AddrGenerator.resolve(args.targets[0])
        return kwargs


class DHCPRetriever(ResultParser[dhcp6.DHCP6], DHCPBaseScanner):
    linkaddr: str
    trid: int

    retrieve_type: type = dhcp6.DHCP6_Advertise

    logger = logging.getLogger('dhcp_retriever')

    def __init__(self,
                 linkaddr: Optional[str] = None,
                 trid: Optional[int] = None,
                 **kwargs):
        super().__init__(**kwargs)
        self.linkaddr = linkaddr if linkaddr is not None else self.target
        self.trid = trid if trid is not None else random.getrandbits(16)

    def retrieve(self) -> Optional[dhcp6.DHCP6]:
        try:
            self.scan_and_parse()
            return self.result
        except Exception:
            return None

    @override(ResultParser)
    def parse(self):
        for pkt in self.recv_pkts:
            _, _, buf = pkt
            try:
                msg = self.parse_msg(buf)
                if isinstance(msg, self.retrieve_type):
                    self.result = msg
                    return
            except Exception as e:
                self.logger.debug('except while parsing: %s', e)
        raise RuntimeError('no response')

    @override(DHCPBaseScanner)
    def send_reset(self):
        self.result = None

    @override(DHCPBaseScanner)
    def send(self):
        self.send_pkts_with_retry()


class DHCPRequester(DHCPRetriever):
    retrieve_type = dhcp6.DHCP6_Reply

    @override(DHCPBaseScanner)
    def get_pkt(self) -> tuple[str, int, bytes]:
        buf = self.build_inforeq(linkaddr=self.linkaddr, trid=self.trid)
        return (self.target, 547, buf)


class DHCPSoliciter(DHCPRetriever):
    retrieve_type = dhcp6.DHCP6_Advertise

    @override(DHCPBaseScanner)
    def get_pkt(self) -> tuple[str, int, bytes]:
        buf = self.build_solicit(linkaddr=self.linkaddr, trid=self.trid)
        return (self.target, 547, buf)
