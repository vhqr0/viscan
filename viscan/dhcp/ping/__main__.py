import json
import argparse

from ...defaults import (
    RETRY,
    TIMEWAIT,
    INTERVAL,
)
from ...utils.generators import AddrGenerator
from .pinger import DHCPPinger


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-o', '--output')
    parser.add_argument('-R', '--retry', type=int, default=RETRY)
    parser.add_argument('-T', '--timewait', type=float, default=TIMEWAIT)
    parser.add_argument('-I', '--interval', type=float, default=INTERVAL)
    parser.add_argument('target')
    args = parser.parse_args()

    output = args.output
    target = AddrGenerator.resolve(args.target)
    retry = args.retry
    timewait = args.timewait
    interval = args.interval

    scanner = DHCPPinger(target=target,
                         retry=retry,
                         timewait=timewait,
                         interval=interval)

    scanner.scan()
    results = scanner.parse()

    if output is not None:
        json.dump(results, open(output, 'w'))
    else:
        for k, v in results.items():
            print(f'{k}:\t{v}')


if __name__ == '__main__':
    main()
