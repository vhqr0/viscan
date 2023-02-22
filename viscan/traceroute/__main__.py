import json
import argparse

from ..defaults import (
    RETRY,
    TIMEWAIT,
    INTERVAL,
    TRACEROUTE_LIMIT,
)
from ..utils.generators import AddrGenerator
from .scanners import TracerouteScanner


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-o', '--output')
    parser.add_argument('-L', '--limit', default=TRACEROUTE_LIMIT)
    parser.add_argument('-R', '--retry', type=int, default=RETRY)
    parser.add_argument('-T', '--timewait', type=float, default=TIMEWAIT)
    parser.add_argument('-I', '--interval', type=float, default=INTERVAL)
    parser.add_argument('target')
    args = parser.parse_args()

    output = args.output
    limit = args.limit
    target = AddrGenerator.resolve(args.target)
    retry = args.retry
    timewait = args.timewait
    interval = args.interval

    scanner = TracerouteScanner(target=target,
                                limit=limit,
                                retry=retry,
                                timewait=timewait,
                                interval=interval)

    scanner.scan()
    results = scanner.parse()

    if output is not None:
        json.dump(results, open(output, 'w'))
    else:
        for i, addr in enumerate(results):
            print(f'{i+1}\t{addr}')


if __name__ == '__main__':
    main()
