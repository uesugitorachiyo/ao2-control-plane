#!/usr/bin/env python3
"""Run the complete Cargo test surface with a safe POSIX fd limit."""

import os
import subprocess
import sys


MIN_NOFILE = 4096
CARGO_TEST_COMMAND = ["cargo", "test", "--workspace", "--all-targets"]


def prepare_nofile_limit(os_name, resource_module=None):
    if os_name == "nt":
        return
    if resource_module is None:
        import resource as resource_module

    soft, hard = resource_module.getrlimit(resource_module.RLIMIT_NOFILE)
    unlimited = getattr(resource_module, "RLIM_INFINITY", -1)
    if hard != unlimited and hard < MIN_NOFILE:
        raise RuntimeError(
            f"RLIMIT_NOFILE hard limit is {hard}, below required {MIN_NOFILE}; "
            "raise the process hard limit and rerun scripts/run-workspace-tests.py"
        )
    if soft < MIN_NOFILE:
        resource_module.setrlimit(resource_module.RLIMIT_NOFILE, (MIN_NOFILE, hard))


def main():
    try:
        prepare_nofile_limit(os.name)
    except (OSError, RuntimeError, ValueError) as error:
        print(f"cannot prepare workspace tests: {error}", file=sys.stderr)
        return 2
    return subprocess.call(CARGO_TEST_COMMAND)


if __name__ == "__main__":
    raise SystemExit(main())
