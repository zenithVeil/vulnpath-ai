import os
import subprocess

# UNSAFE: if it is unsafe flage it
def unsafe_a(user_input):
    os.system("ping " + user_input)

def unsafe_b(user_input):
    subprocess.run(f"ls {user_input}", shell=True)

# SAFE: if it is safe flag it
def safe_c():
    os.system("clear")  # constant, user data is not used

def safe_d():
    subprocess.run(["ls", "-l"])  # shell is not used, user data is not used

def safe_e(user_input):
    subprocess.run(["ls", "-l", user_input])  # shell is not used, user data is used