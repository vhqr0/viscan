from ..defaults import DNS_LIMIT
from ..utils.argparser import GenericScanArgParser
from .scanners import DNSScanner


def main():
    parser = GenericScanArgParser()
    parser.add_limit_dwim(DNS_LIMIT)
    args = parser.parse_args()

    limit = args.limit
    no_recursive = args.no_recursive
    skip_check_autogen = args.skip_dwim
    basename = args.targets[0] if len(args.targets) >= 1 else 'ip6.arpa.'
    nameserver = args.target[1] if len(args.targets) >= 2 else None

    scanner = DNSScanner(basename=basename,
                         nameserver=nameserver,
                         limit=limit,
                         no_recursive=no_recursive,
                         skip_check_autogen=skip_check_autogen,
                         **parser.scan_kwargs)
    scanner.scan()
    results = scanner.parse()

    if not parser.try_output(results):
        for result in results:
            print(result)


if __name__ == '__main__':
    main()
