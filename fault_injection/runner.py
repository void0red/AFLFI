#!/usr/bin/env python3
import argparse
import os
import subprocess
import sys
import logging
import ctypes
from multiprocessing.shared_memory import SharedMemory
import re


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--failth', type=int)
    parser.add_argument('--debug', action='store_true')
    parser.add_argument('exe', type=str, nargs=argparse.REMAINDER)
    return parser.parse_args()


# typedef struct ctl_block {
# uint32_t on;
# uint32_t hit;

# uint32_t fail_size;
# uint32_t enable_size;
# uint32_t disable_size;
# uint32_t trace_size;
#
# uint32_t fails[MAX_FAIL_SIZE];
# uint64_t enable_addr[MAX_ENABLE_SIZE];
# uint64_t disable_addr[MAX_DISABLE_SIZE];
# uint64_t trace_addr[0];
# } __attribute__((packed)) ctl_block_t;

class CtlBlock(ctypes.Structure):
    _pack_ = 1
    _fields_ = [('on', ctypes.c_uint32),
                ('hit', ctypes.c_uint32),
                ('fail_size', ctypes.c_uint32),
                ('enable_size', ctypes.c_uint32),
                ('disable_size', ctypes.c_uint32),
                ('trace_size', ctypes.c_uint32),
                ('fails', ctypes.c_uint32 * 16),
                ('enable_addr', ctypes.c_uint64 * 32),
                ('disable_addr', ctypes.c_uint64 * 128),
                ('trace_addr', ctypes.c_uint64)]


class LogParser:
    def __init__(self, out: bytes):
        logging.debug(out.decode())
        pattern = re.compile(b'failth (\d+), addr (.+?)\n')
        r = re.findall(pattern, out)
        logging.warning(r)


class Runner:
    def __init__(self, cmd: [str], idx: int = 0):
        self.bin = cmd[0]
        self.cmd = cmd

        self.shm_name = f'fj.runner.{idx}'
        self.shm = SharedMemory(self.shm_name, create=True, size=(4 << 10))

        self.env = os.environ.copy()
        self.env.update(AFL_DEBUG='1', __fault_injection_id=self.shm_name)

    def __set_ctl_block(self, *args, **kwargs):
        b = bytes(CtlBlock(*args, **kwargs))
        self.shm.buf[:len(b)] = b

    def __read_ctl_block(self):
        b = CtlBlock.from_buffer_copy(self.shm.buf)
        return b

    def execute(self, *args, **kwargs):
        self.__set_ctl_block(*args, **kwargs)
        r = subprocess.run(self.cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=self.env)
        return self.__read_ctl_block(), LogParser(r.stderr)

    def run_one(self, failth):
        return self.execute(on=2, fail_size=1, fails=(ctypes.c_uint32 * 16)(failth, ))

    def loop(self):
        ctl, log = self.execute(on=1)
        logging.warning(bytes(ctl.hit))
        for i in range(ctl.hit):
            self.execute(on=2, fail_size=1, fails=(ctypes.c_uint32 * 16)(i, ))

    def __del__(self):
        self.shm.close()
        self.shm.unlink()


if __name__ == '__main__':
    parm = get_args()
    if parm.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.WARN)
    r = Runner(parm.exe)
    if parm.failth:
        r.run_one(parm.failth)
    else:
        r.loop()
