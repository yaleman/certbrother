import os
from pathlib import Path

from click.testing import CliRunner

from certbrother import cli


def test_hello_world() -> None:

  if os.getenv("CI"): # running in github actions
    Path('.env').write_text(Path('.env.example').read_text())
  runner = CliRunner()
  result = runner.invoke(cli, ['--help'])
  assert result.exit_code == 0

def test_check() -> None:
  """ tests the check command """
