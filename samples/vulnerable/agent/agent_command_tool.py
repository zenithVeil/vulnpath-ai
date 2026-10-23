# Vulnerable: LLM tool runs shell with user/tool input concatenated (command injection)
import os
import subprocess


def run_agent_tool(user_input):
    # BAD: user-controlled input concatenated into a shell command string
    os.system("echo " + user_input)
    subprocess.run("curl " + user_input, shell=True)
    # Fix suggestion: use subprocess.run([fixed_binary, user_input]) with no shell=True
