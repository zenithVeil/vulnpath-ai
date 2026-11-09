# Safe: agent tool resolves a tool/user-supplied path and verifies it stays
# inside the allowed workspace directory before opening it.
from pathlib import Path

AGENT_WORKSPACE = "/app/agent_workspace"


def read_agent_file(user_path):
    # SAFE: resolve the workspace root, join the user path, resolve again, and
    # confirm the resolved target stays under the workspace before opening it.
    base = Path(AGENT_WORKSPACE).resolve()
    target = (base / user_path).resolve()
    if not target.is_relative_to(base):
        raise ValueError("requested path escapes the agent workspace")
    return open(target, "r", encoding="utf-8").read()
