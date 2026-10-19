#!/usr/bin/env python
"""run_all.py -- convenience runner for the whole evidence chain.

Inside the reproduction container (working directory /work/poc, host poc/ mounted):

    python run_all.py

It builds the three packages and drives the product's gate, the sink and the product
entry point against each arm, printing the same output the individual commands print.
The screenshots in ../screenshots were taken with the individual commands listed in
../截图与复现指引.md; this script is only the "one command" shortcut.
"""

import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent

STEPS = [
    ["make_poc.py"],
    ["run_poc.py", "gate", "out/positive/Z-Image-Turbo"],
    ["run_poc.py", "shard", "out/positive/Z-Image-Turbo"],
    ["run_poc.py", "load", "out/positive/Z-Image-Turbo"],
    ["run_poc.py", "shard", "out/negative/Z-Image-Turbo"],
    ["run_poc.py", "shard", "out/missing/Z-Image-Turbo"],
]


def main():
    for step in STEPS:
        print("")
        print("#" * 78)
        print("# python " + " ".join(step))
        print("#" * 78)
        result = subprocess.run([sys.executable, *step], cwd=HERE)
        if result.returncode != 0 and step[0] == "make_poc.py":
            return result.returncode
    return 0


if __name__ == "__main__":
    sys.exit(main())
