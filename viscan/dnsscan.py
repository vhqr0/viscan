import random

import dns.resolver
import dns.query
import dns.message

from typing import Any, Optional
from argparse import Namespace

from .defaults import DNS_LIMIT
from .common.base import ResultParser, Sender, MainRunner, BaseScanner
from .common.decorators import override
from .common.argparser import ScanArgParser


class DNSScanner(ResultParser[list[str]], Sender, MainRunner, BaseScanner):
    basename: str
    nameserver: str
    limit: int
    no_recursive: bool
    skip_check_autogen: bool
    via_tcp: bool

    SUFFIX = 'ip6.arpa.'
    SUFFIXLEN = len(SUFFIX)

    def __init__(self,
                 basename: str = SUFFIX,
                 nameserver: Optional[str] = None,
                 limit: int = DNS_LIMIT,
                 no_recursive: bool = False,
                 skip_check_autogen: bool = False,
                 via_tcp: bool = False,
                 **kwargs):
        super().__init__(**kwargs)
        if not basename.endswith(self.SUFFIX):
            raise ValueError(f'invalid base name: {basename}')
        self.basename = basename
        self.nameserver = nameserver if nameserver is not None else \
            self.get_nameserver()
        self.limit = 2 * limit + self.SUFFIXLEN
        self.no_recursive = no_recursive
        self.skip_check_autogen = skip_check_autogen
        self.via_tcp = via_tcp

    @override(ResultParser)
    def show(self):
        assert self.result is not None
        for name in self.result:
            print(name)

    @override(BaseScanner)
    def scan_and_parse(self):
        results: list[str] = []
        try:
            if not self.skip_check_autogen and self.check_autogen():
                raise RuntimeError('autogen zone detected')
            self.traversal(self.basename, results)
        except Exception as e:
            self.logger.debug('except while scanning: %s', e)
        self.result = results

    def traversal(self, name: str, results: list[str] = []):
        if len(name) > self.limit or not self.query_noerror(name):
            return
        if len(name) == self.limit:
            self.logger.debug('traversal %s', name)
            results.append(name)
            return
        for c in '0123456789abcdef':
            self.traversal(f'{c}.{name}', results)

    def check_autogen(self) -> bool:
        c = 0
        for _ in range(16):
            a = '.'.join(random.randbytes(16).hex())
            name = f'{a}.{self.basename}'
            name = name[-(64 + self.SUFFIXLEN):]
            if self.query_noerror(name):
                c += 1
                if c >= 4:
                    return True
        return False

    def query_noerror(self, name) -> bool:
        try:
            query = dns.message.make_query(name, 'PTR')
            if self.no_recursive:
                query.flags = 0
            if self.via_tcp:
                res = dns.query.tcp(query, self.nameserver)
            else:
                res = dns.query.udp(query, self.nameserver, self.send_timewait)
            if res.rcode() == 0:
                return True
        except Exception as e:
            self.logger.debug('query %s failed: %s', name, e)
        return False

    def get_nameserver(self) -> str:
        resolver = dns.resolver.get_default_resolver()
        return resolver.nameservers[0]

    @classmethod
    @override(MainRunner)
    def get_argparser(cls, *args, **kwargs) -> ScanArgParser:
        parser = super().get_argparser(*args, **kwargs)
        parser.add_limit_dwim(DNS_LIMIT)
        parser.add_argument('--tcp', action='store_true')
        return parser

    @classmethod
    @override(MainRunner)
    def parse_args(cls, args: Namespace) -> dict[str, Any]:
        kwargs = super().parse_args(args)
        kwargs['limit'] = args.limit_dwim
        kwargs['no_recursive'] = args.no_dwim
        kwargs['skip_check_autogen'] = args.skip_dwim
        kwargs['via_tcp'] = args.tcp
        if len(args.targets) >= 1:
            kwargs['basename'] = args.targets[0]
        if len(args.targets) >= 2:
            kwargs['nameserver'] = args.targets[1]
        return kwargs


if __name__ == '__main__':
    DNSScanner.main()
