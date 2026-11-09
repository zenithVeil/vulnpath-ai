# Safe: agent tool resolves a tool/user-supplied path (which resolves symlinks)
# and verifies it stays inside the allowed workspace directory before opening it.
from pathlib import Path

AGENT_WORKSPACE = "/app/agent_workspace"


def read_agent_file(user_path):
    # SAFE: resolve() follows symlinks to the real on-disk target, then
    # is_relative_to(base) confirms the resolved path stays under the workspace,
    # blocking symlink escape outside the workspace.
    base = Path(AGENT_WORKSPACE).resolve()
    target = (base / user_path).resolve()
    if not target.is_relative_to(base):
        raise ValueError("requested path escapes the agent workspace")
    return open(target, "r", encoding="utf-8").read()
