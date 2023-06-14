#!/usr/bin/env python3
from dataclasses import dataclass
import argparse
from pathlib import Path


@dataclass
class Func:
    name: str
    checked: int
    unchecked: int
    eh: dict

    def __str__(self):
        return f'{self.name},{self.checked},{self.unchecked},{self.checked / (self.checked + self.unchecked)}\n'

    __repr__ = __str__

    def do_filter(self, threshold, sim):
        if 'alloc' in self.name:
            return self
        if self.checked / (self.checked + self.unchecked) < threshold:
            return None
        self.eh = {k: v for k, v in self.eh.items() if v < sim}
        return self

    def loc(self):
        return '#' + self.__str__() + '\n' + '\n'.join(self.eh.keys()) + '\n'


global_locs = {}


def parse(file):
    n, c, uc, eh = '', 0, 0, {}
    ret = []
    with open(file) as f:
        for line in f.readlines():
            line = line.strip()
            if line.startswith('#'):
                if c != 0 or uc != 0:
                    ret.append(Func(n, c, uc, eh.copy()))
                    eh.clear()
                n, *o = line[1:].strip().split(',')
                c = int(o[0])
                uc = int(o[1])
                continue
            h, v = line.split(',')
            try:
                v = float(v)
            except ValueError:
                global_locs[h] = v
                v = 0.0
            if (h in eh and v < eh[h]) or (h not in eh):
                eh[h] = v
    return ret


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='gen loc.txt and func.txt from analyzer result')
    parser.add_argument('--input', type=str, help='analyzer result file', default='analyzer.log')
    parser.add_argument('--filter', type=float, default=0.7)
    parser.add_argument('--sim', type=float, default=0.9)
    parser.add_argument('--debug', action='store_true')
    args = parser.parse_args()
    assert Path(args.input).exists()

    funcs = parse(args.input)

    loc_file = open('loc.txt', 'w')
    func_file = open('func.txt', 'w')
    for i in funcs:
        if i.do_filter(args.filter, args.sim):
            loc_file.write(i.loc())
            func_file.write(str(i))
    loc_file.close()
    func_file.close()

    if args.debug:
        l = [(i, i.checked / (i.unchecked + i.checked)) for i in funcs if i.unchecked != 0]
        for i in sorted(l, key=lambda x: x[1], reverse=True):
            print(i[0])
            for k, v in i[0].eh.items():
                if v == 0.0 and k in global_locs:
                    print(k, global_locs[k])
