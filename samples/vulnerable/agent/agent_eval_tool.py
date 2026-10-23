# Vulnerable: eval/exec on model or tool output


def process_model_output(output):
    # BAD: evaluating model/tool output as code
    return eval(output)
    # Fix suggestion: avoid eval/exec; parse output with a safe parser instead
