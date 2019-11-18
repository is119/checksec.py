import csv
import json
import os
import sys
from argparse import ArgumentParser
from platform import platform

from colorclass import Color
from tabulate import tabulate

import Analyze_ELF
import Analyze_OS
import Analyze_PE


def engine(file_path):
    if not os.path.exists(file_path):
        return {}

    sig = open(file_path, 'rb').read(4)
    if sig.startswith(b'\x7fELF'):
        return Analyze_ELF.analyze_ELF(file_path)
    if sig.startswith(b'MZ'):
        return Analyze_PE.analyze_PE(file_path)
    return {}


def parse_args():
    parser = ArgumentParser(description='Check Security of Excutables')
    parser.add_argument('-c', '--csv', dest='csv', action='store_true', default=False, help='save result as csv')
    parser.add_argument('-j', '--json', dest='json', action='store_true', default=False, help='save result as json')
    parser.add_argument('-o', '--os', dest='os', action='store_true', default=False, help='check os security')
    parser.add_argument(dest='file_paths', metavar='file_path', nargs='*')
    args = parser.parse_args()
    if not args.os and not args.file_paths:
        parser.error('required arguments: file_path or -o')
    return args


def color_wrapper(color, result):
    return Color('{%s}%s{/%s}' % (color, result, color))


def result_color_wrapper(result):
    return color_wrapper(['red', 'green'][bool(result)], result)


def main():
    args = parse_args()

    if args.os:
        os_result = Analyze_OS.analyze_system()
        columns = os_result.keys()
        values = map(result_color_wrapper, os_result.values())
        print('os:', platform())
        print(tabulate([columns, values], tablefmt='plain'), end='\n\n')

    results = {}
    for file_path in args.file_paths:
        result = engine(file_path)
        if result:
            results[file_path] = result
        else:
            print('Warn: not executable file: %s' % file_path, file=sys.stderr)
    
    if not results:
        return

    for file_path, result in results.items():
        columns = result.keys()
        values = map(result_color_wrapper, result.values())
        print('file_path:', file_path)
        print(tabulate([columns, values], tablefmt='plain'), end='\n\n')

    # file
    if args.csv:
        columns = ['file_path'] + list(columns)
        with open('result.csv', 'w', newline='') as f:
            w = csv.writer(f)
            w.writerow(columns)

            for file_path, result in results.items():
                values = [file_path] + list(result.values())
                w.writerow(values)

    if args.json:
        with open('result.json', 'w') as f:
            json.dump(results, f, ensure_ascii=False)


if __name__ == '__main__':
    main()
