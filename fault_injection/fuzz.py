#!/usr/bin/env python3
import os
import signal
import threading
import subprocess
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
        ret.update(concat_cmd(Path(out).joinpath(i), new_bin))
    return ret


gcov_file = '''
#!/usr/bin/bash
exec llvm-cov-14 gcov "$@"
'''
gcov_file_path = '/tmp/llvm-gcov'


def collect_coverage(build_dir):
    try:
        subprocess.run(
            f'lcov --rc lcov_branch_coverage=1 --gcov-tool {gcov_file_path} -c -d {build_dir} -o report.{int(time.time())}.info',
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30, shell=True)
    except subprocess.TimeoutExpired:
        pass


def simple_check(build_dir):
    if not Path(gcov_file_path).exists():
        with open(gcov_file_path, 'w') as f:
            f.write(gcov_file)
        os.chmod(gcov_file_path, 0o777)
    for d, _, fs in os.walk(build_dir):
        for f in fs:
            if f.endswith('.gcno'):
                return True
    return False


if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument('out', type=str, help='afl fuzz output')
    parser.add_argument('bin', type=str, help='target bin with cov inst')
    parser.add_argument('--fuzz', action='store_true')
    parser.add_argument('--build', type=str, help='build dir contains gcno', default='.')
    sys_args = parser.parse_args()
    assert Path(sys_args.out).exists()
    assert simple_check(sys_args.build)
    subprocess.run(f'lcov -z -d {sys_args.build}', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=True)
    if os.environ.get('FJ_FIFUZZ'):
        sys_args.fuzz = True

    pool = RunnerPool(os.cpu_count(), 30)
    fuzzed = set()
    threading.Timer(60 * 30, collect_coverage, (sys_args.build,)).start()
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
            loop.run_until_complete(pool.run_cmd(sys_args.fuzz, False, *cmd.split()))
        print(f'\ncost {time.time() - start}s')
