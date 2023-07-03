#!/usr/bin/env python3
import logging
import os
from argparse import ArgumentParser
from pathlib import Path
from runner import RunnerPool


def read_cmd(fn):
    with open(fn) as f:
        return f.read().splitlines()


def concat_cmd(instance):
    cmds_ = read_cmd(Path(instance).joinpath('cmdline'))
    # current not support stdin input
    assert '@@' in cmds_
    idx = cmds_.index('@@')
    ret = set()
    for fn in os.listdir(Path(instance).joinpath('queue')):
        cmds_[idx] = str(fn)
        ret.add(' '.join(cmds_))
    return ret


def get_all_cmd(out):
    ret = set()
    for i in os.listdir(out):
        ret.update(concat_cmd(Path(out).joinpath(i)))
    return ret


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    parser = ArgumentParser()
    parser.add_argument('out', type=str, help='afl fuzz output')
    sys_args = parser.parse_args()
    assert Path(sys_args.out).exists()

    pool = RunnerPool(os.cpu_count(), 30)
    fuzzed = set()
    while True:
        cmds = get_all_cmd(sys_args.out) - fuzzed
        fuzzed.update(cmds)
        logging.info(f'fetch {len(cmds)} new testcase')
        for cmd in cmds:
            pool.run_cmd(False, False, *cmd.split())
