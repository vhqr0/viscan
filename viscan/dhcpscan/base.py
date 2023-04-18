import random

import scapy.layers.dhcp6 as dhcp6

from typing import Any, Optional
from argparse import Namespace

from ..defaults import (
    DHCP_LIMIT,
    DHCP_ENUM_PLEN,
    DHCP_ENUM_DIFF,
    DHCP_SCALE_COUNT,
    DHCP_SCALE_LOSSRATE,
    DHCP_LOCATE_STEP,
    DHCP_LOCATE_RETRY,
)
from ..common.base import ResultParser, MainRunner
from ..common.dgram import UDPScanner
from ..common.decorators import override
from ..common.argparser import ScanArgParser
from ..common.generators import AddrGenerator


class DHCPBaseScanner(UDPScanner, MainRunner):
    target: str
    linkaddr: str
    limit: int
    plen: int
    diff: int
    count: int
    lossrate: float
    step: int
    retry: int
    duid: dhcp6.DUID_LL

    udp_addr = ('::', 547)

    def __init__(self,
                 target: str,
                 linkaddr: Optional[str] = None,
                 limit: int = DHCP_LIMIT,
                 plen: int = DHCP_ENUM_PLEN,
                 diff: int = DHCP_ENUM_DIFF,
                 count: int = DHCP_SCALE_COUNT,
                 lossrate: float = DHCP_SCALE_LOSSRATE,
                 step: int = DHCP_LOCATE_STEP,
                 retry: int = DHCP_LOCATE_RETRY,
                 **kwargs):
        super().__init__(**kwargs)
        self.target = target
        self.linkaddr = linkaddr if linkaddr is not None else target
        self.limit = limit
        self.plen = plen
        self.diff = diff
        self.count = count
        self.lossrate = lossrate
        self.step = step
        self.retry = retry
        self.duid = dhcp6.DUID_LL(lladdr=random.randbytes(6))

    def build_inforeq(self,
                      linkaddr: Optional[str] = None,
                      trid: Optional[int] = None) -> bytes:
        linkaddr = linkaddr if linkaddr is not None else self.linkaddr
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
        linkaddr = linkaddr if linkaddr is not None else self.linkaddr
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
        parser.add_limit_dwim(DHCP_LIMIT)
        parser.add_plen_dwim(DHCP_ENUM_PLEN)
        parser.add_diff_dwim(DHCP_ENUM_DIFF)
        parser.add_count_dwim(DHCP_SCALE_COUNT)
        parser.add_lossrate_dwim(DHCP_SCALE_LOSSRATE)
        parser.add_step_dwim(DHCP_LOCATE_STEP)
        parser.add_retry_dwim(DHCP_LOCATE_RETRY)
        return parser

    @classmethod
    @override(MainRunner)
    def parse_args(cls, args: Namespace) -> dict[str, Any]:
        kwargs = super().parse_args(args)
        kwargs['limit'] = args.limit_dwim
        kwargs['plen'] = args.plen_dwim
        kwargs['diff'] = args.diff_dwim
        kwargs['count'] = args.count_dwim
        kwargs['lossrate'] = args.lossrate_dwim
        kwargs['step'] = args.step_dwim
        kwargs['retry'] = args.retry_dwim
        kwargs['target'] = AddrGenerator.resolve(args.targets[0])
        if len(args.targets) >= 2:
            kwargs['linkaddr'] = AddrGenerator.resolve(args.targets[1])
        return kwargs


class DHCPRetriever(ResultParser[dhcp6.DHCP6], DHCPBaseScanner):
    retrieve_type: type[dhcp6.DHCP6]

    def __init__(self, trid: Optional[int] = None, **kwargs):
        super().__init__(**kwargs)
        self.trid = trid if trid is not None else random.getrandbits(16)

    def retrieve(self,
                 linkaddr: Optional[str] = None) -> Optional[dhcp6.DHCP6]:
        if linkaddr is not None:
            self.linkaddr = linkaddr
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
                if isinstance(msg, self.retrieve_type) and \
                   msg.trid == self.trid:
                    self.result = msg
                    return
            except Exception as e:
                self.logger.debug('except while parsing: %s', e)
        raise RuntimeError('no response')

    @override(DHCPBaseScanner)
    def send_reset(self):
        super().send_reset()
        self.result = None

    @override(DHCPBaseScanner)
    def send(self):
        self.send_pkts_with_retry()


class DHCPRequester(DHCPRetriever):
    retrieve_type = dhcp6.DHCP6_Reply

    @override(DHCPRetriever)
    def get_pkt(self) -> tuple[str, int, bytes]:
        self.trid += 1
        buf = self.build_inforeq(trid=self.trid)
        return (self.target, 547, buf)


class DHCPSoliciter(DHCPRetriever):
    retrieve_type = dhcp6.DHCP6_Advertise

    @override(DHCPRetriever)
    def get_pkt(self) -> tuple[str, int, bytes]:
        self.trid += 1
        buf = self.build_solicit(trid=self.trid)
        return (self.target, 547, buf)
