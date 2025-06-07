#!/usr/bin/env python3

import sys
import struct

for fn in sys.argv[1:]:
    mirror = f"{fn}.fuzzin"
    print(mirror)

    MIN_DATA = 2048-4
    MIN_CONTROL = 2048-4

    with open(mirror, "wb") as out:
        inp = open(fn, "rb").read()
        if len(inp) < MIN_DATA:
            inp = inp + bytes([0]) * (MIN_DATA - len(inp))
        out.write(struct.pack(">I", len(inp)))
        out.write(inp)

        control = bytes([0x85]) * MIN_CONTROL
        out.write(struct.pack(">I", len(control)))
        out.write(control)
