import time
import threading
import json
import logging

from typing import Generic, TypeVar, Any, Optional
from argparse import Namespace

from ..defaults import (
    LOG_FORMAT,
    LOG_DATEFMT,
    SEND_RETRY,
    SEND_TIMEWAIT,
    SEND_INTERVAL,
)
from .decorators import override
from .argparser import ScanArgParser


class Loggable:
    """Auto add logger based on class name."""

    logger: logging.Logger

    def __init_subclass__(cls, **kwargs):
        cls.logger = logging.getLogger(cls.__name__)
        super().__init_subclass__(**kwargs)

    def __init__(self, **kwargs):
        for k in kwargs:
            self.logger.debug('unused kwarg: %s', k)


class BaseScanner(Loggable):

    @classmethod
    def main(cls):
        raise NotImplementedError

    def scan_and_parse(self):
        try:
            self.scan()
        except Exception as e:
            self.logger.error('error while scanning: %s', e)
            raise

        try:
            self.parse()
        except Exception as e:
            self.logger.error('error while parsing: %s', e)
            raise

    def scan_and_export(self):
        self.scan_and_parse()

        try:
            self.export()
        except Exception as e:
            self.logger.error('error while exporting: %s', e)
            raise

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
        logging.basicConfig(level='DEBUG' if args.debug else 'INFO',
                            format=LOG_FORMAT,
                            datefmt=LOG_DATEFMT)
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
    send_retry: int
    send_timewait: float
    send_interval: float

    def __init__(self,
                 send_retry: int = SEND_RETRY,
                 send_timewait: float = SEND_TIMEWAIT,
                 send_interval: float = SEND_INTERVAL,
                 **kwargs):
        super().__init__(**kwargs)
        self.send_retry = send_retry
        self.send_timewait = send_timewait
        self.send_interval = send_interval

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
        time.sleep(self.send_interval)

    def send_pkts_with_timewait(self, pkts: Optional[list[SendPkt]] = None):
        if pkts is None:
            pkts = self.get_pkts()
        for pkt in pkts:
            self.send_pkt_with_interval(pkt)
        time.sleep(self.send_timewait)

    def send_pkts_with_retry(self, pkts: Optional[list[SendPkt]] = None):
        if pkts is None:
            pkts = self.get_pkts()
        for _ in range(self.send_retry):
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
        kwargs['send_retry'] = args.send_retry
        kwargs['send_timewait'] = args.send_timewait
        kwargs['send_interval'] = args.send_interval
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
