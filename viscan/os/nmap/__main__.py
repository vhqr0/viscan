from ...utils.argparser import GenericScanArgParser
from ...utils.generators import AddrGenerator
from .scanners import NmapFingerPrinter


def main():
    parser = GenericScanArgParser()
    args = parser.parse_args()

    open_port = args.open_port
    closed_port = args.closed_port
    target = AddrGenerator.resolve(args.targets[0])

    scanner = NmapFingerPrinter(target=target,
                                open_port=open_port,
                                closed_port=closed_port,
                                **parser.scan_kwargs)
    scanner.scan()
    results = scanner.parse()

    if not parser.try_output(results):
        for name, fp in results.items():
            print(f'{name}\t{fp}')


if __name__ == '__main__':
    main()
