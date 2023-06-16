#!/usr/bin/env python3
import sys
import os
import subprocess
import logging
from pathlib import Path


def get_bc_name(old, link=False):
    if old.endswith('.o'):
        return old.removesuffix('.o') + '.bc'
    if link:
        return old + '.link.bc'
    return old + '.bc'


def handle_bitcode_mode(l: list):
    logging.debug('recv: ' + ' '.join(l))

    compile_mode = False
    link_mode = False
    outfile_idx = 0
    fixed_args = ['clang'] + l[1:]

    if '-c' in l:
        compile_mode = True
    if '-o' in l:
        outfile_idx = l.index('-o') + 1
        # skip asm
        if l[outfile_idx].endswith('.s') or l[outfile_idx].endswith('.S'):
            return fixed_args
    if '-' in l:
        # it will read from stdin as input later, so we skip it
        return fixed_args
    if l[-1].endswith('.s') or l[-1].endswith('.S'):
        return fixed_args

    multi_objs = [v for i, v in enumerate(l) if v.endswith('.o') and i != outfile_idx]

    if len(multi_objs) > 0:
        link_mode = True

    if compile_mode:
        if outfile_idx > 0:
            tmp_args = ['clang', '-emit-llvm', '-g'] + l[1:outfile_idx] + [get_bc_name(l[outfile_idx])]
            if outfile_idx + 1 < len(l):
                tmp_args += l[outfile_idx + 1:]
            logging.debug(' '.join(tmp_args))
            try:
                subprocess.run(tmp_args, env=os.environ, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception as e:
                logging.info(e)
        else:
            fixed_args = ['clang', '-emit-llvm', '-g'] + l[1:]
    elif link_mode:
        if outfile_idx > 0:
            tmp_args = ['llvm-link', '-o', get_bc_name(l[outfile_idx], True)] + [get_bc_name(i) for i in multi_objs]
            logging.debug(' '.join(tmp_args))
            try:
                subprocess.run(tmp_args, env=os.environ, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception as e:
                logging.info(e)
        else:
            # we can't guess the output name
            pass
    return fixed_args


def handle_afl_mode(l: list):
    afl_cc = Path(__file__).parent.parent.joinpath('afl-clang-fast')
    assert afl_cc.exists()
    return [str(afl_cc)] + l[1:]


if __name__ == '__main__':
    if os.environ.get('HOOK_DEBUG'):
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO, filename='compile.log')

    env = os.environ

    if env.get('HOOK_RAW'):
        new_args = ['clang'] + sys.argv[1:]
        logging.info(' '.join(new_args))
    elif env.get('FJ_FUNC') or \
            env.get('FJ_LOC') or \
            env.get('FJ_DIS') or \
            env.get('AFL_USE_ASAN') or \
            env.get('AFL_USE_UBSAN'):
        new_args = handle_afl_mode(sys.argv)
    else:
        new_args = handle_bitcode_mode(sys.argv)

    logging.info(' '.join(new_args))
    r = subprocess.run(new_args, env=env)
    exit(r.returncode)
