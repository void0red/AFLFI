#!/usr/bin/env python3
import sys
import os
import subprocess
from pathlib import Path

if __name__ == '__main__':
    afl_cc = Path(__file__).parent.parent.joinpath('afl-clang-fast').absolute()
    assert afl_cc.exists()

    errs = Path(os.getcwd()).joinpath('errs.filter.txt').absolute()
    if not errs.exists():
        errs = Path(os.getcwd()).joinpath('errs.txt').absolute()
    assert errs.exists()

    args = [str(afl_cc)]
    args.extend(sys.argv[1:])
    env = os.environ.copy()
    env.update(AFL_USE_ASAN='1', AFL_USE_UBSAN='1', FJ_ERR=str(errs))
    r = subprocess.run(args, env=env)
    exit(r.returncode)
