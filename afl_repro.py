import logging
import struct
from pathlib import Path
import os
import subprocess
from multiprocessing.shared_memory import SharedMemory
from dataclasses import dataclass
import json
import multiprocessing
import argparse
import sys


class ErrorSiteParser:
    def __init__(self, prefix: str = ''):
        self.prefix = prefix
        if self.prefix and not self.prefix.endswith('/'):
            self.prefix = prefix + '/'
        self.root = Path('/tmp/ErrorSite')
        self.items = {}
        self.__fetch_all()

    def __fetch_all(self):
        for file in os.listdir(self.root):
            # make typing happy
            file: str
            with open(self.root.joinpath(file)) as f:
                data = f.readlines()
            for line in data[1:]:
                idx = line.index(',')
                key = int(line[:idx])
                value = line[idx + 1:].strip()
                if self.prefix:
                    source = value.split(',')[-1].replace(':', '#L', 1)
                    value += ',' + self.prefix + source
                self.items[key] = value


@dataclass
class BackTraceFrame:
    idx: int
    addr: int
    func: str
    source: str
    line: int

    def __eq__(self, o):
        assert isinstance(o, self.__class__)
        return self.func == o.func and self.source == o.source and self.line == o.line

    def __hash__(self):
        return hash(f'{self.func}{self.source}{self.line}')


class BackTraceFrameEncoder(json.JSONEncoder):
    def default(self, o):
        return o.__dict__


@dataclass
class ReproResult:
    file: str
    crash_frame: set
    control: list

    def to_dict(self):
        return {'file': str(self.file), 'control': self.control,
                'frame': sorted(list(self.crash_frame), key=lambda x: x.idx)}

    def same_as(self, o):
        assert isinstance(o, self.__class__)
        return self.crash_frame.issubset(o.crash_frame)


class Crash:
    def __init__(self, root: Path, file: Path, error: Path, cmd: [str]):
        self.file = file
        if not error.exists():
            self.error = None
        else:
            self.error = error
        self.cmd = [str(root.joinpath(cmd[0]))]
        self.bin = self.cmd[0]
        self.use_stdin = False
        add_file = False
        for i in cmd[1:]:
            # it seems aflpp_driver uses `-` as stdin
            if i == '@@':
                add_file = True
                self.cmd.append(str(self.file))
            else:
                self.cmd.append(i)
        # append filename at the end
        if not add_file and not self.use_stdin:
            self.cmd.append(str(self.file))

        self.trace = []
        self.control = []
        self.crash_frame = set()

    @staticmethod
    def parse_error_file(file):
        with open(file, 'rb') as f:
            data = f.read()
        size = struct.unpack('=I', data[:4])[0]
        points = struct.unpack('=' + 'I' * size, data[4:])
        return list(points)

    # typedef struct fault_injection_area {
    #   uint64_t status;
    #   uint32_t distance_count;
    #   uint32_t distance;
    #   uint64_t trace[MAX_TRACE];
    #   uint64_t enables[MAX_TRACE];
    # } *FIArea;

    def __init(self, idx: int = 0):
        if not self.error:
            self.sharedmem = None
            self.env = {}
            return
        prefix = '__FAULT_INJECTION_ID'
        self.sharedmem_name = f'fj.repro.{idx}'
        self.sharedmem = SharedMemory(self.sharedmem_name, create=True, size=(16 + (256 << 10)))
        for i in range(16 + (256 << 10)):
            self.sharedmem.buf[i] = 0
        self.trace = self.sharedmem.buf[16:]
        self.enables = self.sharedmem.buf[16 + (128 << 10):]
        self.env = {prefix: self.sharedmem_name, 'AFL_DEBUG': '1'}
        ps = self.parse_error_file(self.error)
        for i in ps:
            self.enables[i >> 3] |= 1 << (i & 7)
            logging.debug(f'enable {i}')
        # remember to enable it
        self.sharedmem.buf[0] = 1

    def __fini(self):
        self.trace = None
        self.enables = None
        if self.sharedmem:
            self.sharedmem.close()
            self.sharedmem.unlink()

    def __handle_stderr(self, stderr):
        for line in stderr.splitlines():
            if line.startswith(b'fj trace'):
                # tid = int(line.split()[-1], 16)
                # self.trace.append(tid)
                pass
            elif line.startswith(b'fj control'):
                cid = int(line.split()[-1], 16)
                if cid not in self.control:
                    self.control.append(cid)
            else:
                logging.debug(f'program stderr: {line.decode()}')
        logging.debug(f'fetch {len(self.trace)} trace, {len(self.control)} control')

    def __handle_coredump(self, core: str):
        p = Path(core)
        if not p.exists():
            logging.debug(f'can not find {p}')
            return
        logging.debug(f'handle core file {core}')
        with subprocess.Popen(args=['/usr/bin/gdb', '-q', '-nx', self.bin, core], stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, cwd='/tmp') as process:
            try:
                stdout, _ = process.communicate(b'bt -frame-info location-and-address -frame-arguments presence\n',
                                                timeout=10)
                for i in stdout.decode().split('#')[2:]:
                    i = i.split()
                    source, line = '', 0
                    if ':' in i[6]:
                        source, line = i[6].split(':')
                    else:
                        source = i[6]
                    frame = BackTraceFrame(int(i[0]), int(i[1], 16), i[3], source, int(line))
                    self.crash_frame.add(frame)
            except:
                process.kill()
        p.unlink()

    def run(self, idx: int | None = None):
        input_data = None
        if self.use_stdin:
            with open(self.file, 'rb') as f:
                input_data = f.read()
        logging.debug(self.cmd)
        if not idx:
            idx = multiprocessing.current_process().pid
        self.__init(idx)
        with subprocess.Popen(args=self.cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              env=self.env, cwd='/tmp') as process:
            try:
                stdout, stderr = process.communicate(input=input_data, timeout=10)
                logging.debug(f'program stdout: {stdout.decode()}')
                self.__handle_stderr(stderr)
                self.__handle_coredump(f'/tmp/core.{process.pid}')
            except:
                process.kill()
        self.__fini()
        return ReproResult(str(self.file), self.crash_frame, self.control)

    def is_same(self, o):
        assert isinstance(o, self.__class__)
        return self.crash_frame.issubset(o.crash_frame)

    def __show_es(self, name: str, es: ErrorSiteParser):
        for i in getattr(self, name):
            if i in es.items:
                print(hex(i), es.items[i])
            else:
                print(hex(i), 'Not Found')

    def show_control(self, es: ErrorSiteParser):
        self.__show_es('control', es)

    def show_trace(self, es: ErrorSiteParser):
        self.__show_es('trace', es)

    def show_frame(self, es: ErrorSiteParser):
        for i in self.crash_frame:
            print(i, f'{es.prefix}{i.source}#L{i.line}')


class FuzzResult:
    def __init__(self, root):
        self.root = Path(root).absolute()
        self.inst = [self.root.joinpath(i) for i in os.listdir(self.root)]

    @staticmethod
    def get_cmd(p: Path):
        with open(p.joinpath('cmdline')) as f:
            lines = [i.strip() for i in f.readlines()]
        return lines

    def get_crash(self):
        ret = []
        for p in self.inst:
            crash_dir = p.joinpath('crashes')
            error_dir = crash_dir.joinpath('.error')
            for i in os.listdir(crash_dir):
                if not i.startswith('id'):
                    continue
                file = crash_dir.joinpath(i)
                error = error_dir.joinpath(i)
                ret.append(Crash(self.root.parent, file, error, self.get_cmd(p)))
        return ret


def parse_command_line():
    parser = argparse.ArgumentParser()
    parser.add_argument('--aflout', type=str)
    parser.add_argument('--prefix', type=str)
    parser.add_argument('--output', type=str, default='crash.json')
    parser.add_argument('--crash', type=str)
    parser.add_argument('--debug', action='store_true')
    return parser.parse_args()


def handle_one_crash(args):
    p = Path(args.crash).absolute()
    assert p.exists()
    es = ErrorSiteParser(args.prefix)
    sync_id = p.parent.parent
    root = p.parent.parent.parent.parent
    error = p.parent.joinpath('.error').joinpath(p.name)
    # root/aflout/sync_id/crashes/file
    c = Crash(root, p, error, FuzzResult.get_cmd(sync_id))
    c.run()
    c.show_control(es)
    c.show_frame(es)


def handle_crashes(args):
    out = FuzzResult(args.aflout)
    crashes = out.get_crash()
    print(f'fetch {len(crashes)} crashes')

    with multiprocessing.Pool(8) as pool:
        r = pool.map(Crash.run, crashes)

    results = []
    for repro in r:
        if not repro:
            continue
        if not repro.crash_frame:
            continue
        if any(filter(lambda c: repro.same_as(c), results)):
            continue
        results.append(repro)

    with open(args.output, 'w') as f:
        f.write('[')
        f.write(','.join(map(lambda res: json.dumps(res.to_dict(), cls=BackTraceFrameEncoder, indent=2), results)))
        f.write(']')

    print(f'write {len(results)} crashes')


if __name__ == '__main__':
    args = parse_command_line()
    if args.debug:
        logging.basicConfig(level=logging.DEBUG)

    if args.crash:
        handle_one_crash(args)
    else:
        handle_crashes(args)
    sys.stdin = sys.__stdin__
    sys.stdout = sys.__stdout__
    sys.stderr = sys.__stderr__
