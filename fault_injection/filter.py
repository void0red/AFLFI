#!/usr/bin/env python3
import sys
from dataclasses import dataclass
import argparse
from pathlib import Path
from collections import Counter


@dataclass
class Func:
    name: str
    checked: int
    unchecked: int
    eh: dict

    def __str__(self):
        title = f'# {self.name},{self.checked},{self.unchecked},{self.checked / (self.checked + self.unchecked)}'
        return title

    __repr__ = __str__

    def do_filter(self, threshold, sim):
        if 'alloc' in self.name:
            return self
        if self.checked / (self.checked + self.unchecked) < threshold:
            return None
        self.eh = {k: v for k, v in self.eh.items() if v < sim}
        return self

    def str(self):
        return self.__str__() + '\n' + '\n'.join(self.eh.keys()) + '\n'


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
            if ',' in line:
                h, v = line.split(',')
            else:
                h, v = line, 0
            if (h in eh and float(v) < eh[h]) or (h not in eh):
                eh[h] = float(v)
    return ret


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--errs', default='errs.txt')
    parser.add_argument('--filter', type=float, default=0.7)
    parser.add_argument('--sim', type=float, default=0.9)
    parser.add_argument('--out', default='errs.filter.txt')
    args = parser.parse_args()
    assert Path(args.errs).exists()

    funcs = parse(args.errs)

    with open(args.out, 'w') as f:
        for i in funcs:
            if i.do_filter(args.filter, args.sim):
                f.write(i.str())
