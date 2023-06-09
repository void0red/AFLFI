#!/usr/bin/env python3
import sys
import os
import subprocess
from pathlib import Path
import logging


def check_args(l: list):
    need_fix = False
    outfile_idx = 0
    if '-c' in l:
        need_fix = True
        if '-o' in l:
            outfile_idx = l.index('-o') + 1
    if '-emit-llvm' in l:
        need_fix = False

    if need_fix:
        ret = ['clang', '-emit-llvm', '-g']
        if outfile_idx > 0:
            ret += l[1:outfile_idx] + [str(Path(l[outfile_idx]).with_suffix('.bc'))]
        if outfile_idx + 1 < len(l):
            ret += l[outfile_idx + 1:]
        return ret
    else:
        return ['clang'] + l[1:]


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG, filename='compile.log')
    new_args = check_args(sys.argv)
    logging.debug(' '.join(new_args))
    r = subprocess.run(new_args, env=os.environ)
    exit(r.returncode)
