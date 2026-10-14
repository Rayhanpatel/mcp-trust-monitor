#!/usr/bin/env python3
"""Run the portable custom-detector consumer outside the repository.

Example: python scripts/check_custom_detector.py --python /tmp/consumer-venv/bin/python
The selected Python must already have the candidate wheel installed. This script
does not install the package, mutate the virtual environment, or add PYTHONPATH.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python", default=sys.executable,
                        help="Python from the environment containing the installed candidate wheel")
    args = parser.parse_args()
    executable = shutil.which(args.python) or str(Path(args.python).resolve())
    source = Path(__file__).resolve().parents[1] / "examples" / "custom_detector_consumer.py"
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    env.pop("VIRTUAL_ENV", None)
    with tempfile.TemporaryDirectory(prefix="mtm-installed-detector-") as temporary:
        directory = Path(temporary)
        consumer = directory / source.name
        shutil.copyfile(source, consumer)
        result = subprocess.run([executable, str(consumer)], cwd=directory, env=env,
                                timeout=400, check=False)
        raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
