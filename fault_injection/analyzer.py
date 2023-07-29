#!/usr/bin/env python3
from dataclasses import dataclass
import argparse
from pathlib import Path
import logging
import random


@dataclass
class Site:
    name: str
    loc: str
    hs: str
    checked: int
    unchecked: int
    check_rate: float
    sim: float
    is_check: bool

    def filter(self, check_rate, sim):
        # if 'alloc' in self.name or 'memalign' in self.name:
        #     return True
        if self.check_rate < check_rate or self.sim > sim:
            return False
        return True

    def __hash__(self):
        return self.hs

    def __eq__(self, o):
        if not isinstance(o, self.__class__):
            return False
        return self.hs == o.hs


# @dataclass
# class Func:
#     name: str
#     checked: int
#     unchecked: int
#     eh: dict

#     def __str__(self):
#         return f'{self.name},{self.checked},{self.unchecked},{self.checked / (self.checked + self.unchecked)}'

#     __repr__ = __str__

#     def do_filter(self, threshold, sim):
#         if 'alloc' in self.name or 'memalign' in self.name:
#             return self
#         if self.checked / (self.checked + self.unchecked) < threshold:
#             return None
#         self.eh = {k: v for k, v in self.eh.items() if v < sim}
#         return self

#     def loc(self):
#         return '#' + self.__str__() + '\n' + '\n'.join(self.eh.keys()) + '\n'
# 
# global_locs = {}


def read_analyzer_log(file) -> [Site]:
    n, c, uc = '', 0, 0
    ret = []
    with open(file) as f:
        for line in f.readlines():
            line = line.strip()
            if line.startswith('#'):
                n, *o = line[1:].strip().split(',')
                c = int(o[0])
                uc = int(o[1])
                continue
            hs, loc, v, *o = line.split(',')
            ret.append(Site(n, loc, hs, c, uc, c / (c + uc), float(v), o != []))
    return ret


def read_defined_funcs(file):
    with open(file) as f:
        data = f.read()
    return data.splitlines()


def read_loc(file):
    ret = set()
    with open(file) as f:
        for line in f.readlines():
            hs = line.split(',')
            if not hs:
                continue
            ret.add(hs[0])
    return ret


def normalize(sites: [Site]):
    group_by_name = {}
    for i in sites:
        group_by_name.setdefault(i.name, []).append(i)
    ret = []
    for k, v in group_by_name.items():
        sims = [i.sim for i in v]
        min_ = min(sims)
        max_ = max(sims)
        if max_ == min_:
            ret.extend(v)
            continue
        for i in v:
            i.sim = (i.sim - min_) / (max_ - min_)
            ret.append(i)
    return ret


def evaluate(sample: [Site], valid: set, check_rate: float, sim: float):
    tp, fp, fn, tn = 0, 0, 0, 0
    for i in sample:
        if i.filter(check_rate, sim):
            if i.hs in valid:
                tp += 1
            else:
                fp += 1
        else:
            if i.hs in valid:
                fn += 1
            else:
                tn += 1
    recall = 0.0
    if tp + fn != 0:
        recall = tp / (tp + fn)
    fprate = 0.0
    if fp + tn != 0:
        fprate = fp / (fp + tn)
    return tp, fp, fn, tn, recall, fprate


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    parser = argparse.ArgumentParser(description='gen loc.txt and func.txt from analyzer result')
    parser.add_argument('--input', type=str, help='analyzer result file', default='analyzer.log')
    parser.add_argument('--check_rate', type=float, default=0.7)
    parser.add_argument('--sim', type=float, default=0.9)
    parser.add_argument('--onlylib', type=bool, default=True)
    parser.add_argument('--funcs', type=str, help='defined func list', default='defined.log')
    parser.add_argument('--debug', action='store_true')
    parser.add_argument('--eva', action='store_true')
    parser.add_argument('--normal', action='store_true', default=True)
    args = parser.parse_args()
    assert Path(args.input).exists()

    sites = read_analyzer_log(args.input)

    if args.normal:
        sites = normalize(sites)

    defined_funcs = []
    if args.onlylib:
        assert Path(args.funcs).exists()
        defined_funcs = read_defined_funcs(args.funcs)

    if args.debug:
        l = [(i, i.check_rate) for i in sites if i.unchecked != 0]
        for i in sorted(l, key=lambda x: x[1], reverse=True):
            print(i[0].name, i[0].loc, i[0].check_rate, i[0].sim)
        exit(0)

    if args.eva:
        sample_size = 100
        total = {i.hs: i for i in sites if i.name not in defined_funcs}
        sample_file = Path('analyzer.sample')
        if not sample_file.exists():
            sample_size = min(sample_size, len(total))
            logging.debug(f'generate {sample_file} with {sample_size} size')
            sample = random.sample(list(total.values()), sample_size)
            with open(sample_file, 'w') as f:
                for i in sample:
                    f.write(f'{i.hs},{i}\n')
            exit(0)
        valid_file = Path('analyzer.valid')
        assert valid_file.exists()

        sample = [total[i] for i in read_loc(sample_file)]
        valid = read_loc(valid_file)

        sample_grain = [i / 10 for i in range(11)]
        with open('analyzer.eva', 'w') as f:
            f.write('check_rate,sim,tp,fp,fn,tn,recallrate,fprate\n')
            for check_rate in sample_grain:
                for sim in sample_grain:
                    r = evaluate(sample, valid, check_rate, sim)
                    f.write(f'{check_rate},{sim},{str(r)[1:-1]}\n')
        logging.debug('generate result in analyzer.eva')
        exit(0)

    old_func, old_loc, new_func, new_loc = set(), set(), set(), set()
    for i in sites:
        if i.name in defined_funcs:
            continue
        old_func.add(i.name)
        old_loc.add(i.hs)
        if not i.filter(args.check_rate, args.sim):
            continue
        new_func.add(i.name)
        new_loc.add(i.hs)

    with open('loc.txt', 'w') as f:
        for i in new_loc:
            f.write(i + '\n')

    with open('func.txt', 'w') as f:
        for i in new_func:
            f.write(i + '\n')

    logging.debug(f'old func {len(old_func)}, old loc {len(old_loc)}, new func {len(new_func)}, new loc {len(new_loc)}')
