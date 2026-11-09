# Vulnerable: agent tool joins a tool/user-supplied path with the workspace and
# opens it with no resolve() and no workspace boundary check. A live symlink
# inside the workspace can point outside it (e.g. a symlink named "data" that
# resolves to "/etc"), letting tool-supplied paths escape via symlink traversal.
from pathlib import Path

AGENT_WORKSPACE = "/app/agent_workspace"


def read_agent_file(user_path):
    # UNSAFE: Path(workspace) / user_path is never resolved, so a symlink inside
    # the workspace that points outside it would not be detected or blocked.
    target = Path(AGENT_WORKSPACE) / user_path
    return open(target, "r").read()
