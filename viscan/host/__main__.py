import sys
import json
import argparse

from ..defaults import INTERVAL
from ..utils.generators import AddrGenerator
from .scanners import HostScanner


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-o', '--output')
    parser.add_argument('-I', '--interval', type=float, default=INTERVAL)
    parser.add_argument('addrs', nargs=argparse.REMAINDER)
    args = parser.parse_args()

    output = args.output
    addrs = args.addrs
    interval = args.interval

    if not addrs:
        for line in sys.stdin:
            line = line.strip()
            if len(line) == 0 or line[0] == '#':
                continue
            addrs.append(line)

    targets = list(AddrGenerator(addrs).addrs)
    scanner = HostScanner(targets, interval=interval)
    scanner.scan()
    results = scanner.parse()

    if output is not None:
        json.dump(results, open(output, 'w'))
    else:
        for addr, state in results:
            print(f'{addr}\t{state}')


if __name__ == '__main__':
    main()
