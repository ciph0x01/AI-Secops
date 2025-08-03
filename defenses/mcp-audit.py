import subprocess
import json
import sys

def run_mcp():
    try:
        proc = subprocess.run(
            'echo \'{"jsonrpc":"2.0","method":"tools/list","id":1}\' | npx -y @chargebee/mcp',
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=30
        )

        output = proc.stdout.strip()

        # Try to parse a full JSON block
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("{"):
                try:
                    parsed = json.loads(line)
                    print(json.dumps(parsed, indent=2))
                    return
                except json.JSONDecodeError:
                    continue

        print("[ERROR] No valid JSON found in MCP output.", file=sys.stderr)
        print(output, file=sys.stderr)

    except subprocess.TimeoutExpired:
        print("[ERROR] MCP CLI timed out.", file=sys.stderr)
    except Exception as e:
        print(f"[ERROR] {e}", file=sys.stderr)

if __name__ == "__main__":
    run_mcp()

