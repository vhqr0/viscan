import random

import scapy.layers.inet6 as inet6

from typing import Any, Optional
from argparse import Namespace

from ..defaults import (
    TRACEROUTE_HOP,
    TRACEROUTE_LIMIT,
)
from ..common.base import ResultParser, MainRunner, SRScanner, BaseScanner
from ..common.decorators import override
from ..common.argparser import ScanArgParser


class RouteSubTracer(ResultParser[Optional[tuple[str, str, bool]]], SRScanner,
                     MainRunner):
    hop: int
    port: int

    def __init__(self, hop: int = TRACEROUTE_HOP, **kwargs):
        super().__init__(**kwargs)
        self.hop = hop
        self.port = random.getrandbits(16)

    def trace(self) -> Optional[tuple[str, str, bool]]:
        for _ in range(self.send_retry):
            try:
                self.scan_and_parse()
                if self.result is not None:
                    break
            except Exception:
                pass
        return self.result

    def get_iperr(
            self,
            pkt: inet6.IPv6) -> Optional[tuple[inet6.IPerror6, str, bool]]:
        if inet6.IPerror6 not in pkt:
            return None
        err = pkt[inet6.IPerror6]
        arrived = False
        if inet6.ICMPv6DestUnreach in pkt:
            unreach = pkt[inet6.ICMPv6DestUnreach]
            if unreach.code == 0:
                reason = 'dest route'
            elif unreach.code == 1:
                reason = 'dest prohibited'
            elif unreach.code == 3:
                reason = 'dest addr'
            elif unreach.code == 4:
                reason = 'dest port'
            else:
                reason = 'dest unknown'
            arrived = True
        elif inet6.ICMPv6TimeExceeded in pkt:
            reason = 'time exceeded'
        else:
            reason = 'unknown'
        return (err, reason, arrived)

    @override(SRScanner)
    def send_reset(self):
        super().send_reset()
        self.result = None

    @override(SRScanner)
    def send(self):
        self.send_pkts_with_timewait()

    @classmethod
    @override(MainRunner)
    def get_argparser(cls, *args, **kwargs) -> ScanArgParser:
        parser = super().get_argparser(*args, **kwargs)
        parser.add_hop_dwim(TRACEROUTE_HOP)
        return parser

    @classmethod
    @override(MainRunner)
    def parse_args(cls, args: Namespace) -> dict[str, Any]:
        kwargs = super().parse_args(args)
        kwargs['hop'] = args.hop_dwim
        return kwargs


class RouteTracer(ResultParser[list[tuple[int, str, str, bool]]], MainRunner,
                  BaseScanner):
    limit: int
    kwargs: dict[str, Any]
    sub_tracer: RouteSubTracer

    sub_tracer_type: type[RouteSubTracer]

    def __init__(self, limit: int = TRACEROUTE_LIMIT, **kwargs):
        super().__init__(**kwargs)
        self.limit = limit
        # assume that subclasses inherit their subtracer's type
        self.kwargs = kwargs
        self.sub_tracer = self.get_sub_tracer()

    def get_sub_tracer(self) -> RouteSubTracer:
        return self.sub_tracer_type(**self.kwargs)

    @override(ResultParser)
    def show(self):
        assert self.result is not None
        for hop, addr, reason, arrived in self.result:
            print(f'{hop}\t{addr}\t{reason}\t{arrived}')

    @override(BaseScanner)
    def scan_and_parse(self):
        results: list[tuple[int, str, str, bool]] = []
        while self.sub_tracer.hop <= self.limit:
            result = self.sub_tracer.trace()
            self.logger.debug('trace %d %s', self.sub_tracer.hop,
                              self.sub_tracer.result)
            if result is None:
                results.append((self.sub_tracer.hop, '', '', False))
            else:
                addr, reason, arrived = result
                results.append((self.sub_tracer.hop, addr, reason, arrived))
                if arrived:
                    break
            self.sub_tracer.hop += 1
        self.result = results

    @classmethod
    @override(MainRunner)
    def get_argparser(cls, *args, **kwargs) -> ScanArgParser:
        parser = super().get_argparser(*args, **kwargs)
        parser.add_limit_dwim(TRACEROUTE_LIMIT)
        return parser

    @classmethod
    @override(MainRunner)
    def parse_args(cls, args: Namespace) -> dict[str, Any]:
        kwargs = super().parse_args(args)
        kwargs['limit'] = args.limit_dwim
        return kwargs
