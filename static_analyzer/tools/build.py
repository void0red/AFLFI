import os
import subprocess
from pathlib import Path
import argparse

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--afl', type=str, required=True, help='afl root')
    parser.add_argument('--ef', type=str, required=True, help='error point file')
    parser.add_argument('--df', type=str, required=True, help='distance file')
    args = parser.parse_args()

    workdir = Path('.').resolve()
    config = workdir.joinpath('configure')
    build_dir = workdir.joinpath('_build')
    CC = Path(args.afl).resolve().joinpath('afl-clang-fast')
    CXX = Path(args.afl).resolve().joinpath('afl-clang-fast++')
    env = {'CC': str(CC), 'CXX': str(CXX), 'AFL_USE_ASAN': '1', 'AFL_USE_UBSAN': '1', 'ERROR_POINT': args.ef,
           'DISTANCE': args.df}

    build_dir.mkdir(0o755, exist_ok=True)

    subprocess.check_call(['make', 'distclean'], shell=True)

    if config.exists():
        try:
            subprocess.check_output(['./configure', '--prefix=', str(build_dir)], shell=True, env=env)
        except subprocess.CalledProcessError as e:
            print(e)
            exit(-1)
    try:
        subprocess.check_output(['make', f'-j{os.cpu_count()}'], shell=True, env=env)
    except subprocess.CalledProcessError as e:
        print(e)
        exit(-1)
