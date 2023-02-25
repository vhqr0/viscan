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
    scanner.parse()
    scanner.output()


if __name__ == '__main__':
    main()
