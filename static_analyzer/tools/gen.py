import os
import subprocess
from dataclasses import dataclass
import re
import argparse
import logging
import networkx as nx
from pathlib import Path
from multiprocessing.pool import Pool


@dataclass
class Record:
    callee: str
    pos: str
    caller: str
    line: str
    similarity: float

    def to_ep_line(self) -> str:
        return '{},{},{}'.format(self.callee, self.caller, self.line)

    def show(self, prefix):
        subset = f'{prefix}\\g<1>#L\\g<2>'
        pattern = re.compile(r'(\S+?):(\d+)?:(\d+)?', re.MULTILINE)
        return re.sub(pattern, subset, self.pos)

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False
        if self.callee == other.callee \
                and self.caller == other.caller \
                and self.line == other.line:
            return True
        return False

    def __hash__(self):
        return hash(self.to_ep_line())


def simple_parser(file):
    with open(file) as f:
        data = f.read()
    ret = []
    for item in data.split('\n\n'):
        lines = item.split('\n')
        callee = lines[0].removeprefix('#').removesuffix(':').strip()
        for i in range(1, len(lines), 2):
            pos = lines[i]
            caller, lineno, sim = lines[i + 1].split(',')
            r = Record(callee, pos, caller, lineno, float(sim))
            ret.append(r)
    return ret


def do_filter(args, records):
    ret = set()
    if args.filter < 1:
        sim = {}
        for i in records:
            sim.setdefault(i.callee, []).append(i)
        for v in sim.values():
            sim_list = [x.similarity for x in v]
            sim_min = min(sim_list)
            factor = max(sim_list) - min(sim_list)
            for r in v:
                if factor == 0:
                    ret.add(r)
                else:
                    sim_normal = (r.similarity - sim_min) / factor
                    if sim_normal < args.filter:
                        ret.add(r)
    else:
        ret = set(records)

    if args.alloc:
        return list(filter(lambda r: 'alloc' in r.callee, ret))


def dump_error_point(file, records):
    with open(file, 'w') as fd:
        for r in records:
            fd.write(r.to_ep_line())
            fd.write('\n')
    logging.info(f'write {len(records)} records to {file}')


class DistanceCalc:
    def __init__(self, file, funcs: dict, weight=False):
        self.G = nx.DiGraph(nx.drawing.nx_pydot.read_dot(file))
        logging.info(self.G)
        self.targets = funcs
        # build map
        self.func_node = {}
        for i in self.G.nodes.data('label'):
            self.func_node[i[1][2:-2]] = i[0]
        logging.info(f'collect {len(self.func_node)} funcs')

    def calc_distance(self, func):
        d = 0.0
        i = 0
        n = self.func_node[func]
        for t in self.targets.keys():
            try:
                shortest = nx.dijkstra_path_length(self.G, n, self.func_node.get(t))
                d += 1.0 / (1.0 + shortest)
                i += 1
            except:
                pass

        if d == 0:
            return None

        return func, i / d

    def run_and_dump(self, file):
        with Pool(os.cpu_count()) as pool:
            fut = pool.map(self.calc_distance, self.func_node.keys())
            with open(file, 'w') as f:
                for res in fut:
                    if res:
                        dis = int(res[1] * 100)
                        f.write(f'{res[0]},{dis}\n')


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser(description='generate errors.txt and distance.txt in current dir')
    parser.add_argument('--sa', type=str, required=True, help='static analyzer')
    parser.add_argument('--bc', type=str, required=True, help='fuzz binary bitcode')
    parser.add_argument('--filter', type=float, default=0.5)
    parser.add_argument('--alloc', default=True, action='store_true')
    parser.add_argument('--prefix', type=str, default='')
    args = parser.parse_args()

    # get callgraph and analyze results
    sa_path = Path(args.sa).resolve().absolute()
    bc_path = Path(args.bc).resolve().absolute()
    assert sa_path.exists() and bc_path.exists()

    subprocess.check_call(['opt', '-enable-new-pm=0', '-disable-output', '--dot-callgraph', str(bc_path)])
    dot_file = bc_path.parent.joinpath(bc_path.name + '.callgraph.dot')
    subprocess.check_call([str(sa_path), str(bc_path)])

    r = simple_parser('result.txt')
    targets = do_filter(args, r)

    dump_error_point('errors.txt', targets)

    targets_func = {}
    for i in targets:
        targets_func.setdefault(i.callee, []).append(i)

    dc = DistanceCalc(dot_file, targets_func)
    dc.run_and_dump('distance.txt')
