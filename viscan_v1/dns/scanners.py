import random
import logging

import dns.resolver
import dns.query
import dns.message
import dns.flags

from typing import Any, Optional, List, Dict
from argparse import Namespace

from ..defaults import DNS_LIMIT
from ..generic.base import BaseScanner, FinalResultMixin, GenericMainMixin
from ..utils.decorators import override
from ..utils.argparser import GenericScanArgParser


class DNSScanner(GenericMainMixin, FinalResultMixin[List[str]], BaseScanner):
    basename: str
    limit: int
    nameserver: str
    no_recursive: bool
    skip_check_autogen: bool
    results: List[str]

    SUFFIX = 'ip6.arpa.'
    SUFFIXLEN = len(SUFFIX)

    # override BaseScanner
    logger = logging.getLogger('dns_scanner')

    def __init__(
            self,
            basename: str = SUFFIX,
            nameserver: Optional[str] = None,
            limit: int = DNS_LIMIT,  # in nibbles, total is 32
            no_recursive: bool = False,
            skip_check_autogen: bool = False,
            **kwargs):
        if not basename.endswith(self.SUFFIX):
            raise ValueError(f'invalid base name: {basename}')
        self.basename = basename
        self.nameserver = nameserver if nameserver is not None \
            else self.get_default_nameserver()
        self.limit = 2 * limit + self.SUFFIXLEN
        self.no_recursive = no_recursive
        self.skip_check_autogen = skip_check_autogen
        self.results = []
        super().__init__(**kwargs)

    @override(BaseScanner)
    def scan(self):
        self.results.clear()

        try:
            if not self.skip_check_autogen and self.check_autogen():
                raise RuntimeError('autogen zone detected')
            self.traversal(self.basename)
        except Exception as e:
            self.logger.error('except while scanning: %s', e)
            raise

    def traversal(self, name):
        if len(name) > self.limit or not self.query_noerror(name):
            return
        if len(name) == self.limit:
            self.results.append(name)
            return
        for c in '0123456789abcdef':
            self.traversal(f'{c}.{name}')

    def check_autogen(self) -> bool:
        c = 0
        for _ in range(16):
            a = '.'.join(random.randbytes(16).hex())
            name = f'{a}.{self.basename}'
            name = name[:64 + self.SUFFIXLEN]
            if self.query_noerror(name):
                c += 1
                if c >= 4:
                    return True
        return False

    def query_noerror(self, name) -> bool:
        try:
            query = dns.message.make_query(name, 'PTR')
            if self.no_recursive:
                query.flags = dns.flags.Flag(0)
            res = dns.query.udp(query, self.nameserver, timeout=self.timewait)
            if res.rcode() == 0:
                return True
        except Exception as e:
            self.logger.debug('query %s failed: %s', name, e)
        return False

    def get_default_nameserver(self) -> str:
        default_resolver = dns.resolver.get_default_resolver()
        return default_resolver.nameservers[0]

    @override(FinalResultMixin)
    def parse(self):
        self.final_result = self.results

    @override(FinalResultMixin)
    def print(self):
        for name in self.final_result:
            print(name)

    @classmethod
    @override(GenericMainMixin)
    def get_argparser(cls, *args, **kwargs) -> GenericScanArgParser:
        parser = super().get_argparser(*args, **kwargs)
        parser.add_limit_dwim(DNS_LIMIT)
        return parser

    @classmethod
    @override(GenericMainMixin)
    def add_scan_kwargs(cls, raw_args: Namespace, scan_kwargs: Dict[str, Any]):
        super().add_scan_kwargs(raw_args, scan_kwargs)
        scan_kwargs['limit'] = raw_args.limit_dwim
        scan_kwargs['no_recursive'] = raw_args.no_recursive
        scan_kwargs['skip_check_autogen'] = raw_args.skip_dwim
        scan_kwargs['basename'] = raw_args.targets[0] \
            if len(raw_args.targets) >= 1 else 'ip6.arpa.'
        scan_kwargs['nameserver'] = raw_args.target[1] \
            if len(raw_args.targets) >= 2 else None
