"""Build and type-check an installed-wheel consumer, including negative controls.

Run: python tests/typing/check.py
Requires uv. Installs mypy and the built wheel in a temporary environment; does
not modify project dependencies. Only this consumer uses --strict: imported
implementations retain their existing gradual typing via --follow-imports=silent.
"""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import tempfile


def main() -> None:
    root = Path(__file__).resolve().parents[2]
    environment = dict(os.environ)
    environment.pop('PYTHONPATH', None)
    with tempfile.TemporaryDirectory(prefix='mtm-public-types-') as temporary:
        work = Path(temporary)
        subprocess.run(['uv', 'build', '--wheel', '--out-dir', str(work / 'dist')],
                       cwd=root, env=environment, check=True)
        subprocess.run(['uv', 'venv', str(work / '.venv')],
                       cwd=work, env=environment, check=True)
        python = work / '.venv' / 'bin' / 'python'
        wheel = next((work / 'dist').glob('*.whl'))
        subprocess.run(['uv', 'pip', 'install', '--python', str(python), 'mypy', str(wheel)],
                       cwd=work, env=environment, check=True)
        for filename in ('consumer.py', 'consumer_invalid.py'):
            shutil.copyfile(root / 'tests' / 'typing' / filename, work / filename)
        check = [str(python), '-m', 'mypy', '--strict', '--follow-imports=silent',
                 '--python-version', '3.10', '--no-incremental']
        subprocess.run([*check, 'consumer.py'], cwd=work, env=environment, check=True)
        negative = subprocess.run([*check, 'consumer_invalid.py'], cwd=work, env=environment,
                                  text=True, capture_output=True)
        print(negative.stdout, end='')
        if (negative.returncode != 1 or 'Found 7 errors in 1 file' not in negative.stdout
                or any(code not in negative.stdout for code in
                       ('[assignment]', '[typeddict-item]', '[arg-type]'))):
            raise RuntimeError('negative consumer did not reject all seven intended errors')
        # Import the installed core with no cloud extras, and prove the package
        # marker lives in that wheel rather than the current source directory.
        subprocess.run([str(python), '-c',
            'import pathlib, sys, mcp_trust_monitor as m; '
            'assert pathlib.Path(m.__file__).with_name("py.typed").is_file(); '
            'assert "openai" not in sys.modules; assert "yaml" not in sys.modules; '
            'print("Installed-wheel core import and py.typed marker verified")'],
            cwd=work, env=environment, check=True)
        print('Public consumer passed; seven invalid uses rejected.')


if __name__ == '__main__':
    main()
