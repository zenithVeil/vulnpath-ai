# Vulnerable: agent tool joins a tool/user-supplied path with the Path "/" operator
# and opens it with NO resolve() and NO workspace boundary check. A value such as
# "../../etc/passwd" lets the path escape the intended agent workspace directory,
# and a live symlink inside the workspace can point outside it as well.
from pathlib import Path

AGENT_WORKSPACE = "/app/agent_workspace"


def read_agent_file(user_path):
    # UNSAFE: Path(workspace) / user_path is joined but never resolved and never
    # checked against the workspace boundary, so ".." segments or symlinks can
    # escape the intended agent workspace directory.
    target = Path(AGENT_WORKSPACE) / user_path
    return open(target, "r").read()
