#!/usr/bin/env python3

import base64
import json
import argparse

import scapy.all as sp

parser = argparse.ArgumentParser()
parser.add_argument('-f', '--file', default='fp.json')
args = parser.parse_args()

data = json.load(open(args.file))

for name, fp_encoded in data.items():
    print(f'--- beg: {name} ---\n')
    if fp_encoded:
        try:
            fp = base64.b64decode(fp_encoded)
            ippkt = sp.IPv6(fp)
            ippkt.show()
        except Exception as e:
            print(f'except while parsing: {e}')
    else:
        print('None')
    print(f'--- end: {name} ---\n')
