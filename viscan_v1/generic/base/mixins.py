import time
import json
import threading
import pprint

from typing import Generic, TypeVar, Any, Optional, List, Dict
from argparse import Namespace

from ...utils.decorators import override
from ...utils.argparser import GenericScanArgParser
from .scanners import MixinForBaseScanner

PktType = TypeVar('PktType')
ResultType = TypeVar('ResultType')
FinalResultType = TypeVar('FinalResultType')


class GenericSendMixin(Generic[PktType], MixinForBaseScanner):
    pkts: List[PktType]
    pkts_idx: int
    pkts_prepared: bool

    stateless: bool = True

    def get_pkts(self) -> List[PktType]:
        raise NotImplementedError

    def prepare_pkts(self) -> bool:
        if self.pkts_prepared:
            return False
        self.pkts = self.get_pkts()
        self.pkts_idx = -1
        self.pkts_prepared = True
        return True

    def prepare_pkt(self) -> bool:
        self.pkts_idx += 1
        return self.pkts_idx < len(self.pkts)

    def send_pkt(self, pkt: PktType):
        raise NotImplementedError

    def send_pkts_with_interval(self):
        while self.prepare_pkt():
            self.send_pkt(self.pkts[self.pkts_idx])
            time.sleep(self.interval)

    def send_pkts_with_retry(self):
        for _ in range(self.retry):
            self.send_pkts_with_interval()
            time.sleep(self.timewait)
            if self.send_pkts_stop_retry():
                break

    def send_pkts_stop_retry(self) -> bool:
        raise NotImplementedError

    def init_send_loop(self):
        self.pkts = []
        self.pkts_idx = -1
        self.pkts_prepared = False

    def stateless_send_loop(self):
        if self.prepare_pkts():
            self.send_pkts_with_interval()

    def stateful_send_loop(self):
        while self.prepare_pkts():
            self.send_pkts_with_retry()

    def send_loop(self):
        if self.stateless:
            self.stateless_send_loop()
        else:
            self.stateful_send_loop()


class GenericReceiveMixin(Generic[ResultType], MixinForBaseScanner):
    results: List[ResultType]

    def lfilter(self, result: ResultType) -> bool:
        return True

    def add_result(self, result: ResultType):
        if self.lfilter(result):
            self.results.append(result)

    def init_receive_loop(self):
        self.results = []

    def receive_loop(self):
        raise NotImplementedError


class GenericScanMixin(GenericSendMixin[PktType],
                       GenericReceiveMixin[ResultType]):
    done: bool

    @override(GenericSendMixin)
    def send_pkts_stop_retry(self):
        return len(self.results) != 0

    def init_scan(self):
        self.done = False
        self.init_send_loop()
        self.init_receive_loop()

    @override(GenericSendMixin)
    def scan(self):
        self.init_scan()

        receiver = threading.Thread(target=self.receive_loop)
        receiver.start()

        exc: Optional[Exception] = None

        try:
            self.send_loop()
        except Exception as e:
            exc = e
            self.logger.error('except while scanning: %s', e)
        finally:
            self.done = True
            receiver.join()

        if exc is not None:
            raise exc


class FinalResultMixin(Generic[FinalResultType], MixinForBaseScanner):
    final_result: FinalResultType

    @override(MixinForBaseScanner)
    def finalize(self):
        try:
            self.parse()
            self.output()
        except Exception as e:
            self.logger.error('except while finalizing: %s', e)
            raise

    def parse(self):
        raise NotImplementedError

    def print(self):
        pprint.pprint(self.final_result)

    def to_jsonable(self) -> Any:
        return self.final_result

    def output(self):
        if self.output_file is not None:
            data = self.to_jsonable()
            json.dump(data, open(self.output_file, 'w'))
        else:
            self.print()


class GenericMainMixin(MixinForBaseScanner):

    @classmethod
    @override(MixinForBaseScanner)
    def main(cls, *args, **kwargs):
        parser = cls.get_argparser(*args, **kwargs)
        raw_args = parser.parse_args()
        scan_kwargs = parser.scan_kwargs
        cls.add_scan_kwargs(raw_args, scan_kwargs)

        scanner = cls(**scan_kwargs)
        scanner.scan()
        scanner.finalize()

    @classmethod
    def get_argparser(cls, *args, **kwargs) -> GenericScanArgParser:
        return GenericScanArgParser(*args, **kwargs)

    @classmethod
    def add_scan_kwargs(cls, raw_args: Namespace, scan_kwargs: Dict[str, Any]):
        pass