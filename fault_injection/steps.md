## General Steps

1. compile the project with [cc.py](./cc.py), this command will generate bitcode(`.bc` file), **CHECK it.**
2. collect all the project bitcode (endswith .bc), better skip the lib strs and feed them into
   the [analyzer](./analyzer.cpp) (e.g. ./build/analyzer), remember use the `onlylib` option,
   e.g. `fd -e bc | xargs ./build/analyzer --onlylib`, this command will generate `analyzer.log`, **CHECK it.**
3. use [analyzer.py](./analyzer.py) to filter the `analyzer.log`, it will find the `analyzer.log` in current workdir,
   and generate `func.txt` and `loc.txt`, **CHECK it.** Pass `--debug` option to work in the debug mode, and find the
   suspicious bugs manually, e.g. `./analyzer.py --debug | bat`
4. recompile the project with [cc.py](./cc.py), remember to set proper environment (use `AFL_USE_ASAN`, `AFL_USE_UBSAN`,
   `FJ_FUNC` now), if it works well, you can see "Load xx from xxx", **CHECK it.**
5. run the [fuzz](../afl-fuzz) or [runner](./runner.py) for testing.

## Environments

### instrumentation

1. AFL_USE_ASAN: AddressSanitizer, used by afl++
2. AFL_USE_UBSAN: UndefinedBehaviourSanitizer, used by afl++
3. FJ_FUNC: fault injection function file absolute path
4. FJ_LOC: fault injection location file absolute path (not reliable)
5. FJ_DIS: fault injection distance file absolute path (reserved, not used now)
6. FJ_FIFUZZ: use fifuzz mode (used for evaluation)

### Runtime

1. AFL_DEBUG: enable debug log
2. FJ_SHM_ID: fault injection shared memory name str, it must be under /dev/shm
3. FJ_SHM_SIZE: fault injection shared memory size, only need when you see a "full track buffer" str (default size: 1M)
4. FJ_DISABLE_RANDOMIZE_CHECK: disable ASLR off check, but we recommend to disable ASLR
5. FJ_FIFUZZ: use fifuzz mode