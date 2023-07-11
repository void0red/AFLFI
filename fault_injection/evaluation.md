## build types

1. bitcode mode, CC=cc.py (no run)
cc.py, gllvm, CFLAGS=-emit-llvm

./distance --list bc.list 
fd -e bc|xargs > bc.list 
--> dis.txt

2. distance mode, CC=cc.py FJ_DIS=dis.txt AFL_USE_ASAN=1 AFL_USE_UBSAN=1

```bash
    1. normal mode, afl-fuzz -S fuzzer0 -o sync_dir -i input_dir -- ./target_binary -a -b @@
    2. distance mode, FJ_FUZZ=1 afl-fuzz -S fuzzer1 -o sync_dir -i input_dir -- ./target_binary -a -b @@
```

3. aflfi mode, FJ_FUNC=func.txt CC=cc.py

```bash
fuzz.py sync_dir ./new_bin
```

4. aflfi loc mode, FJ_LOC=loc.txt CC=cc.py

```bash
fuzz.py sync_dir ./new_bin
```

5. fifuzz mode, FJ_FIFUZZ=1 FJ_FUNC=func.txt CC=cc.py

```bash
FJ_FIFUZZ=1 fuzz.py sync_dir ./new_bin 
```

6. fifuzz loc mode, FJ_FIFUZZ=1 FJ_LOC=loc.txt CC=cc.py

```bash
FJ_FIFUZZ=1 fuzz.py sync_dir ./new_bin
```

7. orignal mode based on loc mode (4)
```bash
fuzz.py sync_dir/fuzzer0 ./new_bin
```

8. orignal mode based on loc mode (4)
```bash
FJ_FIFUZZ=1 fuzzer.py sync_dir/fuzzer0 ./new_bin
```