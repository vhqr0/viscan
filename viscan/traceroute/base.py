import random

from typing import Any, Optional
from argparse import Namespace

from ..defaults import (
    TRACEROUTE_HOP,
    TRACEROUTE_LIMIT,
)
from ..common.base import ResultParser, MainRunner, SRScanner, BaseScanner
from ..common.decorators import override
from ..common.argparser import ScanArgParser


class RouteSubTracer(ResultParser[Optional[tuple[str, bool]]], SRScanner,
                     MainRunner):
    hop: int
    port: int

    def __init__(self, hop: int = TRACEROUTE_HOP, **kwargs):
        super().__init__(**kwargs)
        self.hop = hop
        self.port = random.getrandbits(16)

    def trace(self) -> Optional[tuple[str, bool]]:
        for _ in range(self.send_retry):
            try:
                self.scan_and_parse()
                if self.result is not None:
                    break
            except Exception:
                pass
        return self.result

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


class RouteTracer(ResultParser[list[Optional[str]]], MainRunner, BaseScanner):
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
        for i, addr in enumerate(self.result):
            print(f'{i+1}\t{addr}')

    @override(BaseScanner)
    def scan_and_parse(self):
        results: list[Optional[str]] = []
        while self.sub_tracer.hop <= self.limit:
            result = self.sub_tracer.trace()
            self.logger.debug('trace %d %s', self.sub_tracer.hop,
                              self.sub_tracer.result)
            if result is None:
                results.append(None)
            else:
                addr, arrived = result
                results.append(addr)
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
