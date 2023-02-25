import sys

from ..utils.argparser import GenericScanArgParser
from ..utils.generators import AddrPortGenerator
from .scanners import PortScanner


def main():
    parser = GenericScanArgParser()
    args = parser.parse_args()

    ports = args.ports.split(',')
    addrs = args.targets

    if not addrs:
        for line in sys.stdin:
            line = line.strip()
            if len(line) == 0 or line[0] == '#':
                continue
            addrs.append(line)

    targets = AddrPortGenerator(addrs, ports).addrports
    scanner = PortScanner(targets, **parser.scan_kwargs)

    scanner.scan()
    scanner.parse()
    scanner.output()


if __name__ == '__main__':
    main()
