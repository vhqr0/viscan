import random
import logging

import dns.resolver
import dns.query
import dns.message
import dns.flags

from typing import Optional, List

from ..defaults import DNS_LIMIT
from ..generic.base import BaseScanner
from ..utils.decorators import override


class DNSScanner(BaseScanner):
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

    def parse(self) -> List[str]:
        return self.results

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
