# Vulnerable: pickle.loads on untrusted tool/message payload
import pickle


def handle_tool_message(payload):
    # BAD: unpickling untrusted data can lead to remote code execution
    data = pickle.loads(payload)
    return data
    # Fix suggestion: never unpickle untrusted data; use JSON or a safe format
