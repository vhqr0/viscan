import sys
import json
import argparse

import scapy.all as sp

from ..defaults import (
    INTERVAL,
    POP_PORTS,
)
from ..generators import AddrPortGenerator
from .scanners import PortScanner


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-o', '--output')
    parser.add_argument('-i', '--iface', default=str(sp.conf.iface))
    parser.add_argument('-p', '--ports', default=POP_PORTS)
    parser.add_argument('-I', '--interval', type=float, default=INTERVAL)
    parser.add_argument('addrs', nargs=argparse.REMAINDER)
    args = parser.parse_args()

    output = args.output
    iface = args.iface
    addrs = args.addrs
    ports = args.ports.split(',')
    interval = args.interval

    sp.conf.iface = iface

    if not addrs:
        for line in sys.stdin:
            line = line.strip()
            if len(line) == 0 or line[0] == '#':
                continue
            addrs.append(line)

    targets = AddrPortGenerator(addrs, ports).addrports
    scanner = PortScanner(targets, interval=interval)
    scanner.run()
    results = scanner.parse()

    if output is not None:
        json.dump(results, open(output, 'w'))
    else:
        for addr, port, state in results:
            print(f'[{addr}]:{port}\t{state}')


if __name__ == '__main__':
    main()
