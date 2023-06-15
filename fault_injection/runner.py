#!/usr/bin/env python3
import argparse
import asyncio
import ctypes
import logging
import os
import re
import subprocess
from dataclasses import dataclass, field
from multiprocessing.shared_memory import SharedMemory
from pathlib import Path
import asyncio


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--failth', type=int)
    parser.add_argument('--debug', action='store_true')
    parser.add_argument('--probe', action='store_true')
    parser.add_argument('--thread', action='store_true')
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

    def get_fails(self) -> str:
        return 'fails:' + ','.join([str(self.fails[i]) for i in range(self.fail_size)])


@dataclass
class Symbol:
    exe: str
    func: str = field(init=False, default=None)
    addr: str
    loc: list


@dataclass
class ErrorPoint:
    addr: str
    stack: [Symbol] = field(repr=False)


class Symbolizer:
    head_pattern = re.compile(r'^failth (\d+), addr (.+?)$')
    stack_pattern = re.compile(r'^(.+?),(.+?)\((.+?)?\+(.+?)\) \[(.+?)]$')
    pending_threshold = 1000

    def __init__(self):
        self.pending = {}
        self.cache = {}

    def symbolify(self, text: str) -> str:
        ret = []
        for line in text.splitlines():
            r = re.search(self.stack_pattern, line)
            if r:
                addr1, exe, func, pos, addr2 = r.groups()
                assert addr1 == addr2
                if func:
                    s = Symbol(exe, pos, [])
                    s.func = func
                    ret.append(f'{addr1},{s}')
                else:
                    s = self.__lazy_cache(exe, pos)
                    if isinstance(s, Symbol):
                        ret.append(f'{addr1},{s}')
                    else:
                        ret.append((addr1, exe, pos))
            else:
                ret.append(line)
        self.__check_done()
        for i, v in enumerate(ret):
            if not isinstance(v, str):
                s = self.__lazy_cache(v[1], v[2])
                assert isinstance(s, Symbol)
                ret[i] = f'{v[0]},{s}'
        return '\n'.join(ret)

    # def process(self, text: str):
    #     failth, addr = 0, ''
    #     for line in text.splitlines():
    #         head = re.search(self.head_pattern, line)
    #         if head:
    #             failth, addr = int(head.group(1)), head.group(2)
    #             self.addrs.append(addr)
    #             continue
    #         stack = re.search(self.stack_pattern, line)
    #         if stack:
    #             res = stack.groups()
    #             addr1, exe, func, pos, addr2 = res
    #             assert addr1 == addr2
    #             self.stack.append((addr, exe, func, pos))
    #             if not func:
    #                 self.lazy_cache(exe, pos)
    #
    #     for k, v in self.pending.items():
    #         self.resolve(k, v)
    #     self.pending.clear()
    #
    #     # finally build
    #     last_addr = None
    #     symbols = []
    #     for (addr, exe, func, pos) in self.stack:
    #         if addr != last_addr:
    #             if last_addr:
    #                 self.eps.append(ErrorPoint(last_addr, symbols.copy()))
    #                 symbols.clear()
    #         last_addr = addr
    #
    #         if not func:
    #             symbols.append(self.cache[(exe, pos)])
    #         else:
    #             s = Symbol(exe, pos, [])
    #             s.func = func
    #             symbols.append(s)
    #
    #     self.eps.append(ErrorPoint(last_addr, symbols.copy()))

    def __lazy_cache(self, exe: str, addr: str):
        ret = self.cache.get((exe, addr))
        if ret:
            return ret
        self.pending.setdefault(exe, []).append(addr)
        if len(self.pending[exe]) > self.pending_threshold:
            self.resolve(exe, self.pending.pop(exe))
        return exe, addr

    def __check_done(self):
        for k, v in self.pending.items():
            self.resolve(k, v)
        self.pending.clear()

    def resolve(self, exe: str, addrs: [str]):
        r = subprocess.run(['llvm-addr2line', '-afiC', '-e', exe] + addrs, stderr=subprocess.DEVNULL,
                           stdout=subprocess.PIPE)
        last_addr = None
        current_locs = []
        current_func = None

        for line in r.stdout.decode().splitlines():
            if line in addrs:
                if last_addr:
                    self.cache[(exe, last_addr)] = Symbol(exe, last_addr, current_locs.copy())
                    current_locs.clear()
                last_addr = line
                continue
            if not current_func:
                current_func = line
                continue
            file, lno = line.split(':')
            if file != '??':
                file = str(Path(file).resolve())
            lno = int(lno)
            current_locs.append((file, lno, current_func))
            current_func = None

            # remember to handle last one
            self.cache[(exe, last_addr)] = Symbol(exe, last_addr, current_locs.copy())


class Monitor:
    SYM = Symbolizer()

    def __init__(self, text: str):
        self.raw = text

    def bug(self):
        if 'LeakSanitizer' in self.raw or \
                'AddressSanitizer' in self.raw:
            return True
        return False

    def dump(self, fn):
        with open(fn, 'w') as f:
            f.write(self.SYM.symbolify(self.raw))


class Runner:
    def __init__(self, cmd: [str], idx: int = 0, debug=False):
        self.exe = cmd[0]
        self.args = cmd[1:]
        self.cmd = cmd

        self.id = idx
        self.shm_size = 1 << 20
        self.shm_name = f'fj.runner.{idx}'
        self.shm = SharedMemory(self.shm_name, create=True, size=self.shm_size)

        self.env = os.environ.copy()
        self.env.update(AFL_DEBUG='1', FJ_SHM_ID=self.shm_name, FJ_SHM_SIZE=str(self.shm_size))

    def __set_ctl_block(self, *args, **kwargs):
        b = bytes(CtlBlock(*args, **kwargs))
        self.shm.buf[:len(b)] = b

    def __read_ctl_block(self) -> CtlBlock:
        b = CtlBlock.from_buffer_copy(self.shm.buf)
        return b

    async def __execute(self, *args, **kwargs) -> [CtlBlock, Monitor]:
        self.__set_ctl_block(*args, **kwargs)
        r = await asyncio.create_subprocess_exec(self.exe, *self.args,
                                                 stdout=subprocess.DEVNULL,
                                                 stderr=subprocess.PIPE,
                                                 env=self.env)
        err = await r.stderr.read()
        return self.__read_ctl_block(), Monitor(err.decode())

    async def run_one(self, failth) -> [CtlBlock, Monitor]:
        ctl, mon = await self.__execute(on=2, fail_size=1, fails=(ctypes.c_uint32 * 16)(failth, ))
        logging.debug(f'runner {self.id} fail on {failth}, hit {ctl.hit} errors')
        return ctl, mon

    async def probe(self) -> int:
        ctl, _ = await self.__execute(on=1)
        max_hit = (self.shm_size - ctypes.sizeof(ctl)) // 8
        logging.info(f'probe {ctl.hit} errors, max {max_hit} errors')
        return ctl.hit

    def __del__(self):
        self.shm.close()
        self.shm.unlink()


class RunnerPool:
    def __init__(self, cmd, n, debug=False):
        self.name = Path(cmd[0]).name
        self.runners = asyncio.Queue(n)
        for i in range(n):
            self.runners.put_nowait(Runner(cmd, i, debug))

        self.counter = 0
        self.total = 0

    async def run_one(self, i):
        inst: Runner = await self.runners.get()
        ctl, mon = await inst.run_one(i)
        ctl: CtlBlock
        mon: Monitor
        if mon.bug():
            mon.dump(f'{self.name},runner:{inst.id},{ctl.get_fails()}.log')
        self.runners.put_nowait(inst)
        self.counter += 1
        logging.info(f'task done {self.counter}/{self.total}')

    async def loop(self):
        inst: Runner = await self.runners.get()
        hit = await inst.probe()
        self.runners.put_nowait(inst)
        self.total = hit
        await asyncio.gather(*[self.run_one(i) for i in range(1, hit + 1)])
        logging.critical('ok')


if __name__ == '__main__':
    parm = get_args()
    if len(parm.exe) < 1:
        exit(0)
    if parm.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    if parm.probe:
        asyncio.run(Runner(parm.exe, parm.debug).probe())
    elif parm.failth:
        asyncio.run(Runner(parm.exe, parm.debug).run_one(parm.failth))
    elif parm.thread:
        asyncio.run(RunnerPool(parm.exe, os.cpu_count(), parm.debug).loop())
