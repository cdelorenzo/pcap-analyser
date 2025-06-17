import subprocess
import tempfile
import os
import shutil


def test_bootstrap_poetry_installs_when_missing():
    with tempfile.TemporaryDirectory() as tmpdir:
        env = os.environ.copy()
        env["HOME"] = tmpdir
        env["PATH"] = f"{tmpdir}/.local/bin:" + env["PATH"]
        # Remove poetry if it exists
        shutil.rmtree(f"{tmpdir}/.local", ignore_errors=True)
        result = subprocess.run(
            ["bash", "bin/bootstrap-poetry.sh"],
            capture_output=True,
            text=True,
            env=env,
        )
        assert result.returncode == 0
        assert "INFO: Bootstrap completed successfully" in result.stdout


def test_bootstrap_poetry_detects_existing():
    with tempfile.TemporaryDirectory() as tmpdir:
        env = os.environ.copy()
        env["HOME"] = tmpdir
        env["PATH"] = f"{tmpdir}/.local/bin:" + env["PATH"]
        os.makedirs(f"{tmpdir}/.local/bin", exist_ok=True)
        poetry_path = f"{tmpdir}/.local/bin/poetry"
        with open(poetry_path, "w") as f:
            f.write("#!/bin/sh\necho 'Poetry 1.0.0'")
        os.chmod(poetry_path, 0o755)
        result = subprocess.run(
            ["bash", "bin/bootstrap-poetry.sh"],
            capture_output=True,
            text=True,
            env=env,
        )
        assert result.returncode == 0
        assert "Poetry is already installed." in result.stdout
