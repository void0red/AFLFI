#!/usr/bin/env python3
import argparse
import asyncio
import copy
import ctypes
import logging
import os
import queue
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
                ('disable_addr', ctypes.c_uint64 * 128)]


@dataclass
class Symbol:
    func: str
    off: str
    loc: list
    need_resolve: bool = field(default=False, repr=False)

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
            if v.need_resolve:
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
    def __add_to_list(dst: [TraceStack], o: TraceStack) -> bool:
        for i, v in enumerate(dst):
            if o == v:
                return False
            if o in v:
                return False
            if v in o:
                dst[i] = o
                return False
        dst.append(o)
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
                lno = 0
                if ':' in info:
                    p, lno, _ = info.split(':')
                else:
                    p = info.strip()
                s = Symbol(func, '', [str(Path(p).resolve()), int(lno), func])
            frames.append(s)

        if frames:
            t = TraceStack(frames.copy())
            self.__add_to_list(trace, t)
        return trace


class Monitor:
    Symbolizer_ = Symbolizer()
    CrashAnalyzer_ = CrashAnalyzer()

    def __init__(self, cmd: str, text: str = None):
        logging.debug(text)
        self.cmd = cmd
        self.raw = text

    def process(self, fn) -> bool:
        if not self.raw:
            return False
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


@dataclass
class ErrorSeq:
    hit: int = field(default=0)
    fails: list[int] = field(default_factory=list)

    def gen(self) -> list:
        max_fail = 0
        ret = []
        if self.fails:
            max_fail = self.fails[-1]
        for i in range(max_fail + 1, self.hit + 1):
            seq = copy.deepcopy(self)
            seq.fails.append(i)
            ret.append(seq)
        return ret


class Runner:
    shm_size = 1 << 20
    max_hit = (shm_size - ctypes.sizeof(CtlBlock)) // 8
    logging.info(f'max {max_hit} errors')

    def __init__(self, idx: int = 0):
        self.id = idx
        self.shm_name = f'fj.runner.{idx}'
        self.shm = SharedMemory(self.shm_name, create=True, size=self.shm_size)

        self.env = os.environ.copy()
        self.env.update(AFL_DEBUG='1', FJ_SHM_ID=self.shm_name, FJ_SHM_SIZE=str(self.shm_size))

    def set_ctl_block(self, **kwargs):
        b = bytes(CtlBlock(**kwargs))
        self.shm.buf[:len(b)] = b

    def read_ctl_block(self) -> CtlBlock:
        b = CtlBlock.from_buffer_copy(self.shm.buf)
        return b

    def read_trace(self, size: int):
        if size == 0:
            return set()
        trace = (ctypes.c_uint64 * size).from_buffer(self.shm.buf, ctypes.sizeof(CtlBlock))
        return set(trace)

    async def __execute(self, *args, **kwargs) -> [CtlBlock, Monitor]:
        self.set_ctl_block(**kwargs)
        exe, *cmd = args
        self.proc = await asyncio.create_subprocess_exec(exe, *cmd,
                                                         stdout=subprocess.DEVNULL,
                                                         stderr=subprocess.PIPE,
                                                         env=self.env)
        err = await self.proc.stderr.read()
        return self.read_ctl_block(), Monitor(' '.join(args), err.decode())

    def clean(self):
        self.proc.kill()

    async def run(self, seq: ErrorSeq, *args) -> [CtlBlock, Monitor]:  # self.cmd: list[str] = list(cmd)
        # self.name: str = Path(cmd[0]).name + ',' + str(int(time.time()))
        ctl, mon = await self.__execute(*args, on=2, fail_size=len(seq.fails), fails=(ctypes.c_uint64 * 16)(*seq.fails))
        seq.hit = ctl.hit
        logging.debug(f'runner {self.id} fail on {seq.fails}, hit {ctl.hit} errors')
        return ctl, mon

    async def probe(self, *args) -> CtlBlock:
        ctl, _ = await self.__execute(*args, on=1)
        logging.info(f'probe {ctl.hit} errors')
        return ctl

    def __del__(self):
        self.shm.close()
        self.shm.unlink()


class RunnerPool:
    def __init__(self, n: int, timeout: int):
        self.runners = asyncio.Queue(n)
        for i in range(n):
            self.runners.put_nowait(Runner(i))
        self.timeout = timeout
        self.pending_fault = queue.Queue()
        self.points = set()
        self.finished = 0
        self.total = 0
        self.crashes = 0
        self.timeouts = 0
        self.fifuzz = os.environ.get('FJ_FIFUZZ') is not None

    def __check_new(self, trace: set[int]) -> bool:
        diff = trace - self.points
        if not diff:
            return False
        self.points.update(diff)
        return True

    async def do_fault(self, seq: ErrorSeq, fuzz: bool = False, *args):
        inst: Runner = await self.runners.get()
        try:
            ctl, mon = await asyncio.wait_for(inst.run(seq, *args), self.timeout)
            fails = ','.join([str(i) for i in seq.fails])
            saved = mon.process(f'{Path(args[0]).name},{int(time.time())},{self.crashes},fails:{fails}.log')
            if saved:
                self.crashes += 1
            if fuzz:
                trace = inst.read_trace(ctl.trace_size)
                if self.__check_new(trace):
                    self.pending_fault.put_nowait(seq)
        except asyncio.TimeoutError:
            inst.clean()
            self.timeouts += 1
        self.runners.put_nowait(inst)
        self.finished += 1
        print(f'task done {self.finished}/{self.total}, timeout {self.timeouts}, bug {self.crashes}', end='\r')

    async def run_cmd(self, fuzz=False, force=False, *cmd: str):
        inst: Runner = await self.runners.get()
        hit = 0
        trace = set()
        for i in range(3):
            ctl = await inst.probe(*cmd)
            hit = max(ctl.hit, hit)
            trace.update(inst.read_trace(ctl.trace_size))
        self.runners.put_nowait(inst)
        self.total += hit
        if not force and not self.__check_new(trace):
            logging.debug('can\'t find new points in: ' + ' '.join(cmd))
            return
        init = ErrorSeq(hit)
        await asyncio.gather(*[self.do_fault(seq, fuzz, *cmd) for seq in init.gen()])

        while not self.pending_fault.empty():
            seq: ErrorSeq = self.pending_fault.get_nowait()
            new_seq = seq.gen()
            logging.debug(f'fetch {len(new_seq)} new points')
            self.total += len(new_seq)
            await asyncio.gather(*[self.do_fault(seq, True, *cmd) for seq in new_seq])


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--failth', type=int)
    parser.add_argument('--debug', action='store_true')
    parser.add_argument('--probe', action='store_true')
    parser.add_argument('--thread', action='store_true')
    parser.add_argument('--timeout', type=int, default=30)
    # parser.add_argument('--fast', action='store_true')
    parser.add_argument('--fuzz', action='store_true')
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
        asyncio.run(Runner().probe(*parm.exe))
    elif parm.failth:
        asyncio.run(Runner().run(parm.failth, *parm.exe))
    elif parm.thread:
        pool = RunnerPool(os.cpu_count(), parm.timeout)
        start = time.time()
        asyncio.run(pool.run_cmd(parm.fuzz, False, *parm.exe))
        logging.info(f'\ncost {time.time() - start}s')
