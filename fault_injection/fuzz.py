#!/usr/bin/env python3
import os
import time
from argparse import ArgumentParser
from pathlib import Path
from runner import RunnerPool
import asyncio


def read_cmd(fn):
    with open(fn) as f:
        return f.read().splitlines()


def concat_cmd(instance, new_bin):
    cmds_ = read_cmd(instance / 'cmdline')
    cmds_[0] = new_bin
    # current not support stdin input
    assert '@@' in cmds_
    idx = cmds_.index('@@')
    ret = set()
    for i in os.listdir(instance / 'queue'):
        p = Path(instance / 'queue' / i)
        if p.is_file():
            cmds_[idx] = str(p)
            ret.add(' '.join(cmds_))
    return ret


def get_all_cmd(out, new_bin):
    ret = set()
    for i in os.listdir(out):
        ret.update(concat_cmd(out / i, new_bin))
    return ret


if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument('out', type=str, help='afl fuzz output')
    parser.add_argument('bin', type=str, help='target bin with cov inst')
    sys_args = parser.parse_args()
    assert Path(sys_args.out).exists()

    pool = RunnerPool(os.cpu_count(), 30)
    fuzzed = set()
    start = time.time()
    while True:
        cmds = get_all_cmd(sys_args.out, sys_args.bin) - fuzzed
        fuzzed.update(cmds)
        if len(cmds) == 0:
            os.sched_yield()
            continue
        print(f'\nfetch {len(cmds)} new testcase')
        loop = asyncio.new_event_loop()
        for cmd in cmds:
            loop.run_until_complete(pool.run_cmd(False, False, *cmd.split()))
        print(f'\ncost {time.time() - start}s')
