from click.testing import CliRunner

from certbrother import cli


def test_hello_world() -> None:
  runner = CliRunner()
  result = runner.invoke(cli, ['--help'])
  assert result.exit_code == 0

def test_check() -> None:
  """ tests the check command """
