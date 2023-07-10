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


ignore_file_ext = ['.s', '.S', '.bc']


def handle_bitcode_mode(l: list):
    logging.debug('recv: ' + ' '.join(l))

    compile_mode = False
    link_mode = False
    outfile_idx = 0
    fixed_args = [clang] + l[1:]

    if '-c' in l:
        compile_mode = True
    if '-o' in l:
        outfile_idx = l.index('-o') + 1
        if any([l[outfile_idx].endswith(i) for i in ignore_file_ext]):
            return fixed_args
    if '-' in l:
        # it will read from stdin as input later, so we skip it
        return fixed_args
    if l[-1].endswith('.s') or l[-1].endswith('.S'):
        return fixed_args

    multi_objs = [v for i, v in enumerate(l) if i != outfile_idx and (v.endswith('.o') or v.endswith('.bc'))]

    if len(multi_objs) > 0 or '-shared' in l:
        link_mode = True

    if compile_mode:
        if outfile_idx > 0:
            tmp_args = [clang, '-emit-llvm', '-g'] + l[1:outfile_idx] + [get_bc_name(l[outfile_idx])]
            if outfile_idx + 1 < len(l):
                tmp_args += l[outfile_idx + 1:]
            logging.debug(' '.join(tmp_args))
            try:
                subprocess.run(tmp_args, env=os.environ, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               timeout=30)
            except Exception as e:
                logging.info(e)
        else:
            fixed_args = [clang, '-emit-llvm', '-g'] + l[1:]
    elif link_mode:
        # if outfile_idx > 0:
        #     tmp_args = ['llvm-link', '-o', get_bc_name(l[outfile_idx], True)] + [get_bc_name(i) for i in multi_objs]
        #     logging.debug(' '.join(tmp_args))
        #     try:
        #         subprocess.run(tmp_args, env=os.environ, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        #     except Exception as e:
        #         logging.info(e)
        # else:
        #     # we can't guess the output name
        #     pass
        pass
    return fixed_args


def handle_fault_mode(l: list, fifuzz=False):
    inst_plugin = Path(__file__).parent / 'build' / 'libinst.so'
    rt_o = Path(__file__).parent.parent / 'fj-rt.o'
    fifuzz_rt_o = Path(__file__).parent.parent / 'fifuzz-rt.o'
    assert inst_plugin.exists() and rt_o.exists() and fifuzz_rt_o.exists()
    if fifuzz:
        rt_obj = str(fifuzz_rt_o)
    else:
        rt_obj = str(rt_o)

    ret = [clang, '-g', '-fprofile-arcs', '-ftest-coverage',
           '-fsanitize=address,undefined',
           '-fexperimental-new-pass-manager', '-fpass-plugin=' + str(inst_plugin)]
    if '-c' in l or '-E' in l:
        return ret + l[1:]

    ret += l[1:] + ['--coverage']
    if '-o' in ret:
        ret.insert(ret.index('-o') - 1, rt_obj)
    else:
        ret.append(rt_obj)
    return ret


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
    clang = env.get('CLANG') or 'clang'

    if env.get('HOOK_RAW'):
        new_args = [clang] + sys.argv[1:]
    elif env.get('AFL_USE_ASAN') or env.get('AFL_USE_UBSAN'):
        new_args = handle_afl_mode(sys.argv)
    elif env.get('FJ_FUNC') or env.get('FJ_LOC'):
        new_args = handle_fault_mode(sys.argv, False if env.get('FJ_FIFUZZ') is None else True)
    else:
        new_args = handle_bitcode_mode(sys.argv)
    logging.info(' '.join(new_args))
    try:
        r = subprocess.run(new_args, env=env, timeout=30)
        exit(r.returncode)
    except subprocess.TimeoutExpired:
        r = subprocess.run([clang] + sys.argv[1:])
        exit(r.returncode)
