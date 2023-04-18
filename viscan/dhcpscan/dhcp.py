import socket
import base64

import scapy.layers.dhcp6 as dhcp6

from typing import Any, Optional
from argparse import Namespace

from ..defaults import DHCP_STATELESS_SEARCH_RANGE
from ..common.base import ResultParser, MainRunner
from ..common.decorators import override
from ..common.argparser import ScanArgParser
from .base import DHCPBaseScanner
from .ping import DHCPPinger
from .scale import DHCPScaler, DHCPPoolScale
from .locate import DHCPLocator
from .enum import DHCPEnumerator


class DHCPInfo:
    t: str
    target: str
    linkaddr: str
    plen: int
    reply: dhcp6.DHCP6_Reply
    advertise: dhcp6.DHCP6_Advertise
    subnets: dict[str, Optional[dict[str, Optional[DHCPPoolScale]]]]

    def __init__(self, t: str, target: str, linkaddr: str, plen: int,
                 reply: dhcp6.DHCP6_Reply, advertise: dhcp6.DHCP6_Advertise,
                 subnets: dict[str, Optional[dict[str,
                                                  Optional[DHCPPoolScale]]]]):
        self.t = t
        self.target = target
        self.linkaddr = linkaddr
        self.plen = plen
        self.reply = reply
        self.advertise = advertise
        self.subnets = subnets

    def get_jsonable(self) -> dict[str, Any]:
        subnets_jsonable: dict[str, Optional[dict[str, Any]]] = dict()
        for addr, scales in self.subnets.items():
            if scales is None:
                subnets_jsonable[addr] = None
            else:
                scales_jsonable: dict[str, Any] = dict()
                for name, scale in scales.items():
                    if scale is None:
                        scales_jsonable[name] = None
                    else:
                        scales_jsonable[name] = scale.get_jsonable()
                subnets_jsonable[addr] = scales_jsonable
        return {
            'type': self.t,
            'target': self.target,
            'linkaddr': self.linkaddr,
            'plen': self.plen,
            'reply': base64.b64encode(bytes(self.reply)).decode(),
            'advertise': base64.b64encode(bytes(self.advertise)).decode(),
            'subnets': subnets_jsonable,
        }

    def show(self):
        print(f'type\t{self.t}')
        print(f'target\t{self.target}')
        print(f'linkaddr\t{self.linkaddr}')
        print(f'plen\t{self.plen}')
        print(f'reply\t{self.reply.summary()}')
        print(f'advertise\t{self.advertise.summary()}')
        print('subnets')
        for addr, scales in self.subnets.items():
            print(f'{addr}')
            if scales is not None:
                for name, scale in scales.items():
                    if scale is not None:
                        print(f'{name}\t{scale.summary()}')


class DHCPScanner(ResultParser[DHCPInfo], DHCPBaseScanner):
    kwargs: dict[str, Any]
    stateless_search_range: tuple[int, int, int]

    def __init__(self,
                 stateless_search_range: tuple[int, int, int],
                 sock: Optional[socket.socket] = None,
                 **kwargs):
        sock = sock if sock is not None else self.get_sock()
        kwargs['sock'] = sock
        super().__init__(**kwargs)
        self.kwargs = kwargs
        self.stateless_search_range = stateless_search_range

    def ping(self) -> tuple[dhcp6.DHCP6_Reply, dhcp6.DHCP6_Advertise]:
        pinger = DHCPPinger(**self.kwargs)
        pinger.scan_and_parse()
        assert pinger.result is not None
        reply = pinger.result['reply']
        advertise = pinger.result['advertise']
        if not isinstance(reply, dhcp6.DHCP6_Reply):
            raise RuntimeError('no reply')
        if not isinstance(advertise, dhcp6.DHCP6_Advertise):
            raise RuntimeError('no advertise')
        return reply, advertise

    def scale(self, addr: str) -> dict[str, Optional[DHCPPoolScale]]:
        self.logger.debug('scale %s', addr)
        kwargs = self.kwargs.copy()
        kwargs['linkaddr'] = addr
        scaler = DHCPScaler(**kwargs)
        scaler.scan_and_parse()
        assert scaler.result is not None
        return scaler.result

    def locate(self) -> int:
        locator = DHCPLocator(**self.kwargs)
        locator.scan_and_parse()
        assert locator.result is not None
        return locator.result

    def stateful_enumerate(self, plen: int) -> list[str]:
        kwargs = self.kwargs.copy()
        kwargs['plen'] = plen
        enumerator = DHCPEnumerator(**kwargs)
        enumerator.scan_and_parse()
        assert enumerator.result is not None
        addrs = []
        for addr, msg in enumerator.result:
            if msg is None:
                continue
            if self.get_na(msg) is None and \
               self.get_ta(msg) is None and \
               self.get_pd(msg) is None:
                continue
            addrs.append(addr)
        self.logger.debug('enumerate(%d/%d) %d addrs', plen, self.diff,
                          len(addrs))
        return addrs

    def stateless_enumerate(self, plen: int, diff: int) -> list[str]:
        kwargs = self.kwargs.copy()
        kwargs['plen'] = plen
        kwargs['diff'] = diff
        enumerator = DHCPEnumerator(**kwargs)
        enumerator.scan_and_parse()
        assert enumerator.result is not None
        addrs = []
        for addr, msg in enumerator.result:
            if msg is not None:
                addrs.append(addr)
        self.logger.debug('enumerate(%d/%d) %d addrs', plen, diff, len(addrs))
        return addrs

    def stateful_dispatch(self, reply: dhcp6.DHCP6_Reply,
                          advertise: dhcp6.DHCP6_Advertise):
        self.logger.debug('in stateful dispatch')
        plen = self.locate()
        self.logger.debug('select plen %d', plen)
        addrs = self.stateful_enumerate(plen)
        subnets: dict[str, Optional[dict[str, Optional[DHCPPoolScale]]]]
        if len(addrs) > self.limit:
            self.logger.warning('enumerate too many addrs')
            subnets = {addr: None for addr in addrs}
        else:
            subnets = {addr: self.scale(addr) for addr in addrs}
        self.result = DHCPInfo(t='stateful',
                               target=self.target,
                               linkaddr=self.linkaddr,
                               plen=plen,
                               reply=reply,
                               advertise=advertise,
                               subnets=subnets)

    def stateless_dispatch(self, reply: dhcp6.DHCP6_Reply,
                           advertise: dhcp6.DHCP6_Advertise):
        self.logger.debug('in stateless dispatch')
        results: dict[int, list[str]] = dict()
        beg, end, step = self.stateless_search_range
        limit = self.lossrate * step**2
        for plen in range(beg, end, step):
            results[plen] = self.stateless_enumerate(plen, step)
        plen = self.stateless_plen_select(results, limit)
        self.logger.debug('select plen %d', plen)

        subnets: dict[str, Optional[dict[str, Optional[DHCPPoolScale]]]]
        subnets = {addr: None for addr in results[plen]}
        if self.diff > step:
            addrs = self.stateless_enumerate(plen, self.diff)
            for addr in addrs:
                if addr not in subnets:
                    subnets[addr] = None

        self.result = DHCPInfo(t='stateless',
                               target=self.target,
                               linkaddr=self.linkaddr,
                               plen=plen,
                               reply=reply,
                               advertise=advertise,
                               subnets=subnets)

    def stateless_plen_select(self, results: dict[int, list[str]],
                              limit: float) -> int:
        for addrs in results.values():
            if len(addrs) <= limit:
                break
        else:
            raise RuntimeError('all response stateless server detected')

        # order:
        # 1. max naddrs with inlimit addrs (2 <= len(addrs) <= limit)
        # 2. nearest to 64 with one addr (len(addrs) == 1)
        # 3. min naddrs with outlimit addrs (len(addrs) > limit)
        # 4. 64
        max_inlimit, min_outlimit, nearest_one = None, None, None
        for plen in reversed(results):  # long prefix has higher priority
            naddrs = len(results[plen])
            if 2 <= naddrs <= limit:
                if max_inlimit is None or naddrs > max_inlimit[1]:
                    max_inlimit = (plen, naddrs)
            elif naddrs > limit:
                if min_outlimit is None or naddrs < min_outlimit[1]:
                    min_outlimit = (plen, naddrs)
            elif naddrs == 1:
                dist = abs(plen - 64)
                if nearest_one is None or dist < nearest_one[1]:
                    nearest_one = (plen, dist)

        if max_inlimit is not None:
            return max_inlimit[0]
        if nearest_one is not None:
            return nearest_one[0]
        if min_outlimit is not None:
            return min_outlimit[0]
        return 64

    @override(ResultParser)
    def get_jsonable(self) -> dict[str, Any]:
        assert self.result is not None
        return self.result.get_jsonable()

    @override(ResultParser)
    def show(self):
        assert self.result is not None
        self.result.show()

    @override(DHCPBaseScanner)
    def scan_and_parse(self):
        try:
            reply, advertise = self.ping()
            if self.get_na(advertise) is None and \
               self.get_ta(advertise) is None and \
               self.get_pd(advertise) is None:
                self.stateless_dispatch(reply, advertise)
            else:
                self.stateful_dispatch(reply, advertise)
        except Exception as e:
            self.logger.error('error while scanning: %s', e)
            raise

    @classmethod
    @override(MainRunner)
    def get_argparser(cls, *args, **kwargs) -> ScanArgParser:
        parser = super().get_argparser(*args, **kwargs)
        parser.add_argument('--stateless-search-range',
                            default=DHCP_STATELESS_SEARCH_RANGE)
        return parser

    @classmethod
    @override(MainRunner)
    def parse_args(cls, args: Namespace) -> dict[str, Any]:
        kwargs = super().parse_args(args)
        stateless_search_range = tuple(
            int(i) for i in args.stateless_search_range.split(';'))
        if len(stateless_search_range) != 3:
            raise ValueError('invalid search range')
        kwargs['stateless_search_range'] = stateless_search_range
        return kwargs
