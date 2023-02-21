import json
import argparse

from ..defaults import (
    TIMEWAIT,
    DNS_LIMIT,
)
from .scanners import DNSScanner


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-o', '--output')
    parser.add_argument('-s', '--nameserver')
    parser.add_argument('-L', '--limit', type=int, default=DNS_LIMIT)
    parser.add_argument('-T', '--timewait', type=float, default=TIMEWAIT)
    parser.add_argument('-N', '--no-recursive', action='store_true')
    parser.add_argument('-S', '--skip-check-autogen', action='store_true')
    parser.add_argument('basename')
    args = parser.parse_args()

    output = args.output
    basename = args.basename
    nameserver = args.nameserver
    limit = args.limit
    timewait = args.timewait
    no_recursive = args.no_recursive
    skip_check_autogen = args.skip_check_autogen

    scanner = DNSScanner(basename=basename,
                         limit=limit,
                         nameserver=nameserver,
                         timewait=timewait,
                         no_recursive=no_recursive,
                         skip_check_autogen=skip_check_autogen)
    scanner.scan()
    results = scanner.results

    if output is not None:
        json.dump(results, open(output, 'w'))
    else:
        for result in results:
            print(result)


if __name__ == '__main__':
    main()
