#!/usr/bin/env python3
import os
from argparse import ArgumentParser
from pathlib import Path
from runner import RunnerPool
import asyncio


def read_cmd(fn):
    with open(fn) as f:
        return f.read().splitlines()


def concat_cmd(instance):
    cmds_ = read_cmd(instance / 'cmdline')
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


def get_all_cmd(out):
    ret = set()
    for i in os.listdir(out):
        ret.update(concat_cmd(Path(out).joinpath(i)))
    return ret


if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument('out', type=str, help='afl fuzz output')
    sys_args = parser.parse_args()
    assert Path(sys_args.out).exists()

    pool = RunnerPool(os.cpu_count(), 30)
    fuzzed = set()
    while True:
        cmds = get_all_cmd(sys_args.out) - fuzzed
        fuzzed.update(cmds)
        if len(cmds) > 0:
            print(f'fetch {len(cmds)} new testcase')
        loop = asyncio.new_event_loop()
        for cmd in cmds:
            print(cmd)
            loop.run_until_complete(pool.run_cmd(False, False, *cmd.split()))
