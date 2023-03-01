import time
import json
import threading
import logging

from typing import Generic, TypeVar, Any, Optional
from logging import Logger
from argparse import Namespace

from ..defaults import (
    RETRY,
    TIMEWAIT,
    INTERVAL,
)
from .decorators import override
from .argparser import ScanArgParser


class BaseScanner:
    logger: Logger = logging.getLogger('base_scanner')

    def __init__(self, **kwargs):
        for k in kwargs:
            self.logger.warning('unused kwarg: %s', k)

    @classmethod
    def main(cls):
        raise NotImplementedError

    def scan_and_parse(self):
        try:
            self.scan()
        except Exception as e:
            self.logger.error('error while scanning: %s', e)

        try:
            self.parse()
        except Exception as e:
            self.logger.error('error while parsing: %s', e)

    def scan_and_export(self):
        self.scan_and_parse()

        try:
            self.export()
        except Exception as e:
            self.logger.error('error while exporting: %s', e)

    def scan(self):
        raise NotImplementedError

    def parse(self):
        raise NotImplementedError

    def export(self):
        raise NotImplementedError


class MainRunner(BaseScanner):

    @classmethod
    @override(BaseScanner)
    def main(cls, *args, **kwargs):
        parser = cls.get_argparser(*args, **kwargs)
        kwargs = cls.parse_args(parser.parse_args())
        scanner = cls(**kwargs)
        scanner.scan_and_export()

    @classmethod
    def get_argparser(cls, *args, **kwargs) -> ScanArgParser:
        return ScanArgParser(*args, **kwargs)

    @classmethod
    def parse_args(cls, args: Namespace) -> dict[str, Any]:
        return dict()


Result = TypeVar('Result')


class ResultParser(Generic[Result], MainRunner, BaseScanner):
    result: Optional[Result]
    output_path: Optional[str]

    def __init__(self, output_path: Optional[str] = None, **kwargs):
        super().__init__(**kwargs)
        self.result = None
        self.output_path = output_path

    def get_jsonable(self) -> Any:
        return self.result

    def show(self):
        print(self.result)

    def dump(self, output_path: Optional[str] = None):
        if output_path is None:
            output_path = self.output_path
        if output_path is None:
            raise RuntimeError('no output path specified')
        jsonable = self.get_jsonable()
        json.dump(jsonable, open(output_path, 'w'))

    @override(BaseScanner)
    def export(self):
        if self.output_path is None:
            self.show()
        else:
            self.dump()

    @classmethod
    @override(MainRunner)
    def parse_args(cls, args: Namespace) -> dict[str, Any]:
        kwargs = super().parse_args(args)
        kwargs['output_path'] = args.output_path
        return kwargs


SendPkt = TypeVar('SendPkt')
RecvPkt = TypeVar('RecvPkt')


class Sender(Generic[SendPkt], MainRunner):
    retry: int
    timewait: float
    interval: float

    def __init__(self,
                 retry: int = RETRY,
                 timewait: float = TIMEWAIT,
                 interval: float = INTERVAL,
                 **kwargs):
        super().__init__(**kwargs)
        self.retry = retry
        self.timewait = timewait
        self.interval = interval

    def get_pkt(self) -> SendPkt:
        raise NotImplementedError

    def get_pkts(self) -> list[SendPkt]:
        return [self.get_pkt()]

    def send_pkt(self, pkt: SendPkt):
        raise NotImplementedError

    def send_pkt_with_interval(self, pkt: Optional[SendPkt] = None):
        if pkt is None:
            pkt = self.get_pkt()
        self.send_pkt(pkt)
        time.sleep(self.interval)

    def send_pkts_with_timewait(self, pkts: Optional[list[SendPkt]] = None):
        if pkts is None:
            pkts = self.get_pkts()
        for pkt in pkts:
            self.send_pkt_with_interval(pkt)
        time.sleep(self.timewait)

    def send_pkts_with_retry(self, pkts: Optional[list[SendPkt]] = None):
        if pkts is None:
            pkts = self.get_pkts()
        for _ in range(self.retry):
            self.send_pkts_with_timewait(pkts)
            if self.send_pkts_break_retry():
                break

    def send_pkts_break_retry(self) -> bool:
        raise NotImplementedError

    def send_reset(self):
        pass

    def send(self):
        raise NotImplementedError

    @classmethod
    @override(MainRunner)
    def parse_args(cls, args: Namespace) -> dict[str, Any]:
        kwargs = super().parse_args(args)
        kwargs['retry'] = args.retry
        kwargs['timewait'] = args.timewait
        kwargs['interval'] = args.interval
        return kwargs


class Recver(Generic[RecvPkt]):
    recv_pkts: list[RecvPkt]

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.recv_pkts = []

    def append_recv_pkt(self, pkt: RecvPkt):
        if self.recv_filter(pkt):
            self.recv_pkts.append(pkt)

    def recv_filter(self, pkt: RecvPkt) -> bool:
        return True

    def recv_reset(self):
        self.recv_pkts.clear()

    def recv(self):
        raise NotImplementedError


class SRScanner(Sender[SendPkt], Recver[RecvPkt], BaseScanner):
    scan_done: bool

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.scan_done = False

    def scan_reset(self):
        self.send_reset()
        self.recv_reset()
        self.scan_done = False

    @override(BaseScanner)
    def scan(self):
        self.scan_reset()

        recver = threading.Thread(target=self.recv)
        recver.start()

        exc: Optional[Exception] = None

        try:
            self.send()
        except Exception as e:
            exc = e
        finally:
            self.scan_done = True
            recver.join()

        if exc is not None:
            raise exc

    @override(Sender)
    def send_pkts_break_retry(self) -> bool:
        return len(self.recv_pkts) != 0