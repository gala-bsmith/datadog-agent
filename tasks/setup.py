"""
Helpers for setting up your environment
"""

from __future__ import annotations

import os
import re
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from typing import TYPE_CHECKING

from invoke import task
from invoke.exceptions import Exit

from tasks.libs.common.color import color_message
from tasks.libs.common.status import Status
from tasks.libs.common.utils import running_in_pyapp

if TYPE_CHECKING:
    from collections.abc import Generator

PYTHON_REQUIREMENTS = ["requirements.txt", "tasks/requirements.txt"]


@dataclass
class SetupResult:
    name: str
    status: str
    message: str = ""


@task(default=True)
def setup(ctx):
    """
    Set up your environment
    """
    setup_functions = [
        check_python_version,
        check_go_version,
        check_git_repo,
        update_python_dependencies,
        download_go_tools,
        install_go_tools,
        enable_pre_commit,
    ]

    results = []

    for setup_function in setup_functions:
        output = setup_function(ctx)

        if isinstance(output, Iterable):
            results.extend(output)
        else:
            results.append(output)

    print("\nResults:\n")

    final_result = Status.OK

    for result in results:
        if result.status == Status.FAIL:
            final_result = Status.FAIL
        elif result.status == Status.WARN and final_result == Status.OK:
            final_result = Status.WARN

        print(f"{result.name}\t {color_message(result.status, Status.color(result.status))}")
        if result.message:
            print(color_message(result.message, "orange"))

    print()

    if final_result == Status.OK:
        print(color_message("Setup completed successfully.", "green"))
    elif final_result == Status.WARN:
        print(color_message("Setup completed with warnings.", "orange"))
    else:
        print(color_message("Setup completed with errors.", "red"))
        raise Exit(code=1)


def check_git_repo(ctx) -> SetupResult:
    print(color_message("Fetching git repository...", "blue"))
    ctx.run("git fetch", hide=True)

    print(color_message("Checking main branch...", "blue"))
    output = ctx.run("git rev-list ^HEAD origin/main --count", hide=True)
    count = output.stdout.strip()

    message = ""
    status = Status.OK

    if count != "0":
        status = Status.WARN
        message = f"Your branch is {count} commit(s) behind main. Please update your branch."

    return SetupResult("Check git repository", status, message)


def check_go_version(ctx) -> SetupResult:
    print(color_message("Checking Go version...", "blue"))

    with open(".go-version") as f:
        expected_version = f.read().strip()

    try:
        output = ctx.run("go version", hide=True)
    except:
        return SetupResult(
            "Check Go version", Status.FAIL, f"Go is not installed. Please install Go {expected_version}."
        )

    version = re.search(r'go version go(\d+.\d+.\d+)', output.stdout)

    if version.group(1) != expected_version:
        return SetupResult(
            "Check Go version", Status.FAIL, f"Go version is {version.group(1)}. Please install Go {expected_version}."
        )

    return SetupResult("Check Go version", Status.OK)


def check_python_version(_ctx) -> SetupResult:
    print(color_message("Checking Python version...", "blue"))

    with open(".python-version") as f:
        expected_version = f.read().strip()

    message = ""
    status = Status.OK
    if tuple(sys.version_info)[:2] != tuple(int(d) for d in expected_version.split(".")):
        status = Status.FAIL
        message = (
            f"Python version is {sys.version_info[0]}.{sys.version_info[1]}.{sys.version_info[2]}. "
            f"Please install Python {expected_version}.\n"
            f"We recommend using pyenv to manage your Python versions: https://github.com/pyenv/pyenv#installation"
        )

    return SetupResult("Check Python version", status, message)


def update_python_dependencies(ctx) -> Generator[SetupResult]:
    print(color_message("Updating Python dependencies...", "blue"))

    for requirement_file in PYTHON_REQUIREMENTS:
        print(color_message(f"Updating Python dependencies from {requirement_file}...", "blue"))

        ctx.run(f"pip install -r {requirement_file}", hide=True)
        yield SetupResult(f"Update Python dependencies from {requirement_file}", Status.OK)


def enable_pre_commit(ctx) -> SetupResult:
    print(color_message("Enabling pre-commit...", "blue"))

    status = Status.OK
    message = ""

    if not ctx.run("pre-commit --version", hide=True, warn=True).ok:
        return SetupResult(
            "Enable pre-commit", Status.FAIL, "Please install pre-commit first: https://pre-commit.com/#installation."
        )

    try:
        # Some dd-hooks can mess up with pre-commit
        hooks_path = ctx.run("git config --global core.hooksPath", hide=True).stdout.strip()
        ctx.run("git config --global --unset core.hooksPath", hide=True)
    except Exception:
        hooks_path = ""

    if running_in_pyapp():
        import shutil

        # TODO Remove in a couple of weeks
        # Remove the old devagent file if it exists
        if os.path.isfile(".pre-commit-config-devagent.yaml"):
            os.remove(".pre-commit-config-devagent.yaml")

        # We use a custom version that use deva instead of inv directly, that requires the venv to be loaded
        from pre_commit import update_pyapp_file

        config_file = update_pyapp_file()
        if not shutil.which("deva"):
            status = Status.WARN
            if shutil.which("devagent"):
                message = "`devagent` has been renamed `deva`. Please, rename your binary, no need to download the new version."
            else:
                message = "`deva` is not in your PATH"
    else:
        config_file = ".pre-commit-config.yaml"

    # Uninstall in case someone switch from one config to the other
    ctx.run("pre-commit uninstall", hide=True)
    ctx.run(f"pre-commit install --config {config_file}", hide=True)

    if hooks_path:
        ctx.run(f"git config --global core.hooksPath {hooks_path}", hide=True)

    return SetupResult("Enable pre-commit", status, message)


def install_go_tools(ctx) -> SetupResult:
    print(color_message("Installing go tools...", "blue"))
    status = Status.OK

    try:
        from tasks import install_tools

        install_tools(ctx)
    except:
        status = Status.FAIL

    return SetupResult("Install Go tools", status)


def download_go_tools(ctx) -> SetupResult:
    print(color_message("Downloading go tools...", "blue"))
    status = Status.OK

    try:
        from tasks import download_tools

        download_tools(ctx)
    except:
        status = Status.FAIL

    return SetupResult("Download Go tools", status)
