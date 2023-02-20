import time

from typing import Generic, TypeVar, List

from ...defaults import (
    RETRY,
    TIMEWAIT,
    INTERVAL,
)

PktType = TypeVar('PktType')
ResultType = TypeVar('ResultType')


class GenericScanMixin(Generic[PktType, ResultType]):
    results: List[ResultType]
    pkts: List[PktType]
    pkts_idx: int
    pkts_prepared: bool

    retry: int = RETRY
    timewait: float = TIMEWAIT
    interval: float = INTERVAL

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
        while self.prepare_pkts():
            for _ in range(self.retry):
                self.send_pkts_with_interval()
                time.sleep(self.timewait)
                if self.send_pkts_stop_retry():
                    break

    def send_pkts_stop_retry(self):
        return len(self.results) != 0

    def init_sender(self):
        self.results = []
        self.pkts = []
        self.pkts_idx = -1
        self.pkts_prepared = False

    def stateless_sender(self):
        self.init_sender()
        if not self.prepare_pkts():
            raise RuntimeError('not pkts prepared')
        self.send_pkts_with_interval()

    def stateful_sender(self):
        self.init_sender()
        self.send_pkts_with_retry()

    def lfilter(self, result: ResultType) -> bool:
        return True

    def add_result(self, result: ResultType):
        if self.lfilter(result):
            self.results.append(result)


class StatelessScanMixin:

    def sender(self):
        self.stateless_sender()


class StatefulScanMixin:

    def sender(self):
        self.stateful_sender()
