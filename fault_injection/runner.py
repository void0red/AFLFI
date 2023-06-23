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
import time


# typedef struct ctl_block {
# int32_t on;
# uint32_t hit;
#
# uint32_t fail_size;
# uint32_t enable_size;
# uint32_t disable_size;
# uint32_t trace_size;
#
# uint64_t fail_addr[MAX_FAIL_SIZE];
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
                ('fails', ctypes.c_uint64 * 16),
                ('enable_addr', ctypes.c_uint64 * 32),
                ('disable_addr', ctypes.c_uint64 * 128),
                ('trace_addr', ctypes.c_uint64)]

    def get_fails(self) -> str:
        return 'fails:' + ','.join([str(self.fails[i]) for i in range(self.fail_size)])


@dataclass
class Symbol:
    func: str
    off: str
    loc: list
    need_reslove: bool = field(default=False, repr=False)

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False
        if self.func != other.func:
            return False
        if self.off and other.off and self.off != other.off:
            return False
        if self.loc and other.loc:
            if self.loc[0] != other.loc[0]:
                return False
        return True


@dataclass
class TraceStack:
    frame: [Symbol]

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False
        if len(self.frame) != len(other.frame):
            return False
        for i in range(len(self.frame)):
            if self.frame[i] != other.frame[i]:
                return False
        return True

    def __in(self, other: Symbol):
        for i in self.frame:
            if i == other:
                return True
        return False

    def __contains__(self, item):
        if isinstance(item, Symbol):
            return self.__in(item)
        elif isinstance(item, self.__class__):
            if all([self.__in(i) for i in item.frame]):
                return True
            return False
        else:
            return False

    def __len__(self):
        return len(self.frame)


class Symbolizer:
    stack_pattern = re.compile(r'^(.+?),(.+?)\((.+?)?\+(.+?)\) \[(.+?)]$', re.MULTILINE)
    pending_threshold = 1000

    def __init__(self):
        self.pending = {}
        self.cache = {}

    def process(self, text: str):
        frames = []
        for i in re.finditer(self.stack_pattern, text):
            addr1, exe, func, off, addr2 = i.groups()
            assert addr1 == addr2
            if func:
                s = Symbol(func, off, [])
                frames.append(s)
            else:
                s = self.__lazy_cache(exe, off)
                frames.append(s)
        self.__check_done()
        for i, v in enumerate(frames):
            if v.need_reslove:
                frames[i] = self.cache[(v.func, v.off)]
        return TraceStack(frames)

    def __lazy_cache(self, exe: str, off: str):
        ret = self.cache.get((exe, off))
        if ret:
            return ret
        self.pending.setdefault(exe, []).append(off)
        if len(self.pending[exe]) > self.pending_threshold:
            self.resolve(exe, self.pending.pop(exe))
            return self.cache[(exe, off)]
        return Symbol(exe, off, [], True)

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
        ret = {}

        for line in r.stdout.decode().splitlines():
            if line in addrs:
                if last_addr:
                    ret[(exe, last_addr)] = Symbol(current_locs[0][-1], last_addr, current_locs.copy())
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
            ret[(exe, last_addr)] = Symbol(current_locs[0][-1], last_addr, current_locs.copy())

        self.cache.update(ret)
        return ret


class CrashAnalyzer:
    frame_pattern = re.compile(r"^\s+#(\d+) \S* in (\S+) (\S+)", re.MULTILINE)

    def __init__(self):
        self.LeakSanitizer: [TraceStack] = []
        self.AddressSanitizer: [TraceStack] = []
        self.UndefinedBehaviorSanitizer: [TraceStack] = []

    def process(self, text: str):
        trace = self.do_parse(text)
        if not trace:
            return False, None
        if 'LeakSanitizer: detected memory leaks' in text:
            return self.__add_to_list(self.LeakSanitizer, trace), trace
        elif 'AddressSanitizer' in text:
            return self.__add_to_list(self.AddressSanitizer, trace), trace
        elif 'UndefinedBehaviorSanitizer' in text:
            return self.__add_to_list(self.UndefinedBehaviorSanitizer, trace), trace
        else:
            assert text

    @staticmethod
    def __add_to_list(l:[TraceStack], o: TraceStack) -> bool:
        for i, v in enumerate(l):
            if o == v:
                return False
            if o in v:
                return False
            if v in o:
                l[i] = o
                return False
        l.append(o)
        return True
    
    def do_parse(self, text: str) -> [TraceStack]:
        trace = []
        frames = []
        for i in re.finditer(self.frame_pattern, text):
            idx, func, info = i.groups()
            idx = int(idx)
            if idx < len(frames):
                t = TraceStack(frames.copy())
                self.__add_to_list(trace, t)
                frames.clear()
            info = info.removeprefix('(').removesuffix(')')
            if '+' in info:
                exe, off = info.split('+')
                s = Symbol(func, off, [])
            else:
                p, lno, rno = info.split(':')
                s = Symbol(func, '', [str(Path(p).resolve()), int(lno), func])
            frames.append(s)

        if frames:
            t = TraceStack(frames.copy())
            self.__add_to_list(trace, t)
        return trace


class Monitor:
    Symbolizer_ = Symbolizer()
    CrashAnalyzer_ = CrashAnalyzer()
    
    def __init__(self, cmd:str, text: str = None):
        logging.debug(text)
        self.cmd = cmd
        self.raw = text

    def process(self, fn) -> bool:
        need_save, trace = self.CrashAnalyzer_.process(self.raw)
        if not need_save:
            return False
        ep = self.Symbolizer_.process(self.raw)
        # do simple filter here
        with open(fn, 'w') as f:
            f.write(self.cmd + '\n')
            f.write(self.raw + '\n')
            f.write('Inject Error Stack:\n' + str(ep) + '\nSanitizer Stack:\n')
            f.write('\n'.join([str(i) for i in trace]))
        return True
        

    def dump(self, cmd, fn):
        with open(fn, 'w') as f:
            f.write(cmd + '\n')
            f.write(self.ep)


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

    def set_ctl_block(self, *args, **kwargs):
        b = bytes(CtlBlock(*args, **kwargs))
        self.shm.buf[:len(b)] = b

    def read_ctl_block(self) -> CtlBlock:
        b = CtlBlock.from_buffer_copy(self.shm.buf)
        return b

    async def __execute(self, *args, **kwargs) -> [CtlBlock, Monitor]:
        self.set_ctl_block(*args, **kwargs)
        r = await asyncio.create_subprocess_exec(self.exe, *self.args,
                                                 stdout=subprocess.DEVNULL,
                                                 stderr=subprocess.PIPE,
                                                 env=self.env)
        err = await r.stderr.read()
        return self.read_ctl_block(), Monitor(' '.join(self.cmd), err.decode())

    async def run_one(self, failth) -> [CtlBlock, Monitor]:
        ctl, mon = await self.__execute(on=2, fail_size=1, fails=(ctypes.c_uint64 * 16)(failth, ))
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
        self.cmd = ' '.join(cmd)
        self.name = Path(cmd[0]).name + ',' + str(int(time.time()))
        self.runners = asyncio.Queue(n)
        for i in range(n):
            self.runners.put_nowait(Runner(cmd, i, debug))

        self.finished = 0
        self.total = 0
        self.crashes = 0
        self.timeout = 0
        

    async def run_one(self, i):
        inst: Runner = await self.runners.get()
        try:
            ctl, mon = await asyncio.wait_for(inst.run_one(i), 60)
            saved = mon.process(f'{self.name},runner:{inst.id},{ctl.get_fails()}.log')
            if saved:
                self.crashes += 1
        except asyncio.TimeoutError:
            # logging.warning(f'runner {inst.id} timeout, {inst.read_ctl_block().get_fails()}')
            self.timeout += 1
        self.runners.put_nowait(inst)
        self.finished += 1
        print(f'task done {self.finished}/{self.total}, timeout {self.timeout}, bug {self.crashes}', end='\r')

    async def loop(self):
        inst: Runner = await self.runners.get()
        hit = await inst.probe()
        self.runners.put_nowait(inst)
        self.total = hit
        await asyncio.gather(*[self.run_one(i) for i in range(1, hit + 1)])


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--failth', type=int)
    parser.add_argument('--debug', action='store_true')
    parser.add_argument('--probe', action='store_true')
    parser.add_argument('--thread', action='store_true')
    # parser.add_argument('--timeout', type=int, default=60)
    parser.add_argument('exe', type=str, nargs=argparse.REMAINDER)
    return parser.parse_args()


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
        start = time.time()
        asyncio.run(RunnerPool(parm.exe, os.cpu_count(), parm.debug).loop())
        logging.info(f'cost {time.time() - start}s')
