import re
import argparse
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Elem:
    name: str
    checked: int
    unchecked: int
    rate: float
    text1: str = field(repr=False)
    text2: str = field(repr=False)

    def show(self, prefix):
        subset = f'{prefix}\\g<1>#L\\g<2>'
        pattern = re.compile(r'(\S+?):(\d+)?:(\d+)?', re.MULTILINE)
        return re.sub(pattern, subset, self.text1)


def parse_command_line():
    parser = argparse.ArgumentParser()
    parser.add_argument('--file', type=str, default='result.txt')
    parser.add_argument('--prefix', type=str, default='')
    parser.add_argument('--filter', type=float, default=0.3)
    parser.add_argument('--disable', type=str, default='')
    parser.add_argument('--enable', type=str, default='')
    parser.add_argument('--alloc', default=False, action='store_true')
    parser.add_argument('--all', default=False, action='store_true')
    return parser.parse_args()


def do_filter(args, elems: [Elem]) -> [Elem]:
    if args.alloc:
        return list(filter(lambda e: 'alloc' in e.name, elems))
    if args.enable or args.disable:
        enable = args.enable.split(',')
        disable = args.disable.split(',')
        return list(filter(lambda e: e.name in enable and e.name not in disable, elems))
    if args.filter:
        if args.filter > 1:
            args.filter = 1
        es_sorted = sorted(filter(lambda i: i.rate <= 0.5, elems), key=lambda e: e.rate)
        return es_sorted[:int(len(es_sorted) * args.filter)]


def simple_parser(file):
    with open(file) as f:
        data = f.read()
    ret = []
    for item in data.split('\n\n'):
        lines = item.split('\n')
        title = [i for i in lines[0].removeprefix('#').split() if i != '']
        if not title:
            continue
        text1 = []
        text2 = []
        for line in lines[1:]:
            if line.startswith('#'):
                text1.append(line)
            else:
                text2.append(line)
        e = Elem(title[0], int(title[2]), int(title[4]), float(title[6]), '\n'.join(text1), '\n'.join(text2))
        ret.append(e)
    return ret


if __name__ == '__main__':
    args = parse_command_line()
    file_dir = Path(args.file).absolute().parent
    es = simple_parser(args.file)
    es_filtered = do_filter(args, es)
    with open(file_dir.joinpath('error.txt'), 'w') as f:
        if args.all:
            f.write('\n'.join([i.name + ',*,0' for i in es_filtered]))
        else:
            f.write('\n'.join(map(lambda i: i.text2, es_filtered)))

    if args.prefix:
        for i in es_filtered:
            print(i)
            print(i.show(args.prefix))
            print()
