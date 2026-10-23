# Safe: safe parsing, no eval/exec
import ast


def parse_literal(output):
    # GOOD: ast.literal_eval only for trusted literals, no eval/exec
    return ast.literal_eval(output)
