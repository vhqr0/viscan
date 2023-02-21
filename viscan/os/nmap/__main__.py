import json
import argparse

import scapy.all as sp

from ...defaults import (
    RETRY,
    TIMEWAIT,
    INTERVAL,
)
from ...utils.generators import AddrGenerator
from .nmap_scanner import NmapScanner


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-o', '--output')
    parser.add_argument('-i', '--iface', default=str(sp.conf.iface))
    parser.add_argument('-R', '--retry', type=int, default=RETRY)
    parser.add_argument('-T', '--timewait', type=float, default=TIMEWAIT)
    parser.add_argument('-I', '--interval', type=float, default=INTERVAL)
    parser.add_argument('-O', '--open-port', type=int)
    parser.add_argument('-C', '--closed-port', type=int)
    parser.add_argument('target')
    args = parser.parse_args()

    output = args.output
    iface = args.iface
    target = AddrGenerator.resolve(args.target)
    retry = args.retry
    timewait = args.timewait
    interval = args.interval
    open_port = args.open_port
    closed_port = args.closed_port

    sp.conf.iface = iface

    scanner = NmapScanner(target=target,
                          open_port=open_port,
                          closed_port=closed_port,
                          retry=retry,
                          timewait=timewait,
                          interval=interval)

    scanner.scan()
    results = scanner.results

    if output is not None:
        json.dump(results, open(output, 'w'))
    else:
        for name, fp in results.items():
            print(f'{name}\t{fp}')


if __name__ == '__main__':
    main()
