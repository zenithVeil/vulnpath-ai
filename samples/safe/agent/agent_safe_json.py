# Safe: json.loads instead of pickle
import json


def parse_tool_message(payload):
    # GOOD: JSON is a safe serialization format
    return json.loads(payload)
