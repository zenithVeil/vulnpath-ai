# Safe: agent tool resolves a tool/user-supplied path and verifies it stays
# inside the allowed workspace directory before opening it.
import os
from pathlib import Path

AGENT_WORKSPACE = "/app/agent_workspace"


def read_agent_file(filename):
    # SAFE: resolve the workspace root, build the target from the filename's
    # basename only, resolve again, and confirm it stays under the workspace.
    base = Path(AGENT_WORKSPACE).resolve()
    target = (base / Path(filename).name).resolve()
    if not target.is_relative_to(base):
        raise ValueError("requested path escapes the agent workspace")
    return open(target, "r", encoding="utf-8").read()
