import sys

from ..utils.argparser import GenericScanArgParser
from ..utils.generators import AddrGenerator
from .scanners import HostScanner


def main():
    parser = GenericScanArgParser()
    args = parser.parse_args()

    addrs = args.targets

    if len(addrs) == 0:
        for line in sys.stdin:
            line = line.strip()
            if len(line) == 0 or line[0] == '#':
                continue
            addrs.append(line)

    targets = list(AddrGenerator(addrs).addrs)
    scanner = HostScanner(targets, **parser.scan_kwargs)

    scanner.scan()
    results = scanner.parse()

    if parser.output(results):
        for addr, state in results:
            print(f'{addr}\t{state}')


if __name__ == '__main__':
    main()
