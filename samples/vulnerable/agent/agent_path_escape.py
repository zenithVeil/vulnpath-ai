# Vulnerable: agent tool reads a file using a tool/user-supplied path with no
# workspace boundary check. A value such as "../../etc/passwd" lets the path
# escape the intended agent workspace directory.
AGENT_WORKSPACE = "/app/agent_workspace"


def read_agent_file(filename):
    # UNSAFE: tool-supplied filename concatenated directly into the open()
    # call with no workspace boundary check, so the path can escape the
    # intended agent workspace directory.
    return open(AGENT_WORKSPACE + "/" + filename, "r").read()
