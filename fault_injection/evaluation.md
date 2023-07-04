## build types

1. origin mode, CC=afl-clang-fast
2. bitcode mode, CC=cc.py
3. fj mode, FJ_FUNC=func.txt CC=cc.py
4. fj loc mode, FJ_LOC=loc.txt CC=cc.py
5. fifuzz mode, FJ_FIFUZZ=1 FJ_FUNC=func.txt CC=cc.py
6. fifuzz loc mode, FJ_FIFUZZ=1 FJ_LOC=loc.txt CC=cc.py