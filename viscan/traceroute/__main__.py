from ..defaults import TRACEROUTE_LIMIT
from ..utils.argparser import GenericScanArgParser
from ..utils.generators import AddrGenerator
from .scanners import TracerouteScanner


def main():
    parser = GenericScanArgParser()
    parser.add_argument('-L', '--limit', default=TRACEROUTE_LIMIT)
    args = parser.parse_args()

    limit = args.limit
    target = AddrGenerator.resolve(args.targets[0])

    scanner = TracerouteScanner(target=target,
                                limit=limit,
                                **parser.scan_kwargs)

    scanner.scan()
    results = scanner.parse()

    if parser.output(results):
        for i, addr in enumerate(results):
            print(f'{i+1}\t{addr}')


if __name__ == '__main__':
    main()
