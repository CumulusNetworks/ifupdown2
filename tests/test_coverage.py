from typing import List
from pathlib import Path

import pytest
import logging
import tarfile
import coverage
import subprocess

from .conftest import registered_files

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def __doesnt_start_with(file_path: Path, exclude_list: List[str]) -> bool:
    for exclude in exclude_list:
        if str(file_path).startswith(f"tests/{exclude}"):
            return False
    return True


@pytest.mark.order(-2)
def test_orphan_files(skip_if_any_test_failed):
    """
    Check if we have orphaned files in tests/
    Orphaned files might have been used by older test but not used anymore
    This test ensure that all files are used and not stale
    """
    exclude_list = [
        "__pycache__",
        "results",
        "conftest.py",
        "test_l2.py",
        "test_l3.py",
        "test_coverage.py",
        "__init__.py"
    ]
    files = set(str(path) for path in Path("tests/").rglob("*") if path.is_file() and __doesnt_start_with(path, exclude_list))

    if orphan_files := files - registered_files:
        pytest.fail(f"Found orphan files: {orphan_files}")


def extract_tar_gz(archive_path, extract_path):
    """
    Extracts a .tar.gz archive to the specified directory.
    """
    with tarfile.open(archive_path, "r:gz") as archive:
        archive.extractall(path=extract_path)
        logger.info(f"Archive '{archive_path}' successfully extracted to '{extract_path}'.")


@pytest.mark.order(-1)
def test_coverage(ssh):
    if ssh.coverage_enabled:
        # todo move some of those things to a fixture?
        ssh.download_coverage()
        extract_tar_gz("tests/results/coverage_data.tar.gz", "tests/results/")
        cov = coverage.Coverage(data_file="tests/results/coverage_data/.coverage")
        cov.load()
        total_coverage = cov.report(ignore_errors=True)
        assert total_coverage >= 75, f"Coverage less than 75% - total coverage: {total_coverage} - details in ./tests/results/coverage_data.tar.gz"
    else:
        pytest.skip("coverage is disabled")


@pytest.mark.skip(reason="This test is currently disabled because flake8 is currently reporting 3638 errors and polluting the output")
def test_flake8():
    result = subprocess.run(["flake8", "."], text=True, capture_output=True)

    if result.returncode != 0:
        error_count = len(result.stdout.strip().split("\n"))
        pytest.fail(
            f"flake8 reported {error_count} error{'s' if error_count > 1 else ''} (see logs)\n"
            f"{result.stdout}\n"
            f"{result.stderr}\n"
        )


@pytest.mark.skip(reason="This test is currently disabled due to import-not-found errors")
def test_mypy():
    result = subprocess.run(["mypy", "."], text=True, capture_output=True)

    if result.returncode != 0:
        msg = result.stdout.strip().split("\n")[-1]
        pytest.fail(
            f"Mypy {msg}\n"
            f"{result.stdout}\n"
            f"{result.stderr}\n"
        )
