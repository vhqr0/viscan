from ..defaults import TRACEROUTE_LIMIT
from ..utils.argparser import GenericScanArgParser
from ..utils.generators import AddrGenerator
from .scanners import TracerouteScanner


def main():
    parser = GenericScanArgParser()
    parser.add_limit_dwim(TRACEROUTE_LIMIT)
    args = parser.parse_args()

    limit = args.limit_dwim
    target = AddrGenerator.resolve(args.targets[0])

    scanner = TracerouteScanner(target=target,
                                limit=limit,
                                **parser.scan_kwargs)

    scanner.scan()
    results = scanner.parse()

    if not parser.try_output(results):
        for i, addr in enumerate(results):
            print(f'{i+1}\t{addr}')


if __name__ == '__main__':
    main()
