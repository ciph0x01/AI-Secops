from flask import Flask, jsonify, render_template_string, request
import subprocess
import json
import re

app = Flask(__name__)

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang=\"en\">
<head>
  <meta charset=\"UTF-8\">
  <title>Run MCP/Registry Tool</title>
  <script src=\"https://cdn.tailwindcss.com\"></script>
</head>
<body class=\"bg-gray-100 text-gray-800 p-6\">
  <div class=\"max-w-3xl mx-auto bg-white p-6 rounded shadow\">
    <h1 class=\"text-2xl font-bold mb-4\">JSON-RPC Runner for NPM Registry CLI</h1>

    <label for=\"pkg\" class=\"block text-sm font-medium text-gray-700 mb-1\">NPM CLI Package</label>
    <input type=\"text\" id=\"pkg\" placeholder=\"@chargebee/mcp\" value=\"@chargebee/mcp\"
           class=\"w-full px-3 py-2 border rounded mb-4\" />

    <button id=\"runBtn\" class=\"bg-blue-600 text-white px-4 py-2 rounded hover:bg-blue-700\">Run CLI</button>

    <div id=\"tools\" class=\"mt-6 space-y-4\"></div>
    <div id=\"error\" class=\"mt-6 text-red-600 whitespace-pre-wrap hidden\"></div>
  </div>

  <script>
    document.getElementById("runBtn").addEventListener("click", async () => {
      const pkgInput = document.getElementById("pkg").value.trim();
      const toolsDiv = document.getElementById("tools");
      const errorDiv = document.getElementById("error");
      toolsDiv.innerHTML = "";
      errorDiv.classList.add("hidden");

      if (!pkgInput) {
        errorDiv.textContent = "[ERROR] Please provide a package name.";
        errorDiv.classList.remove("hidden");
        return;
      }

      toolsDiv.innerHTML = "<p class='text-sm text-gray-500'>Running CLI for package: " + pkgInput + "...</p>";

      try {
        const response = await fetch("/run-cli?pkg=" + encodeURIComponent(pkgInput));
        const data = await response.json();

        if (!data.success) {
          errorDiv.textContent = `[ERROR] ${data.error}\n\n${data.raw || ''}`;
          errorDiv.classList.remove("hidden");
          return;
        }

        const tools = data.data?.result?.tools || [];
        if (tools.length === 0) {
          toolsDiv.innerHTML = "<p class='text-sm text-gray-500'>No tools found in response.</p>";
          return;
        }

        toolsDiv.innerHTML = tools.map(tool => {
          const suspicious = /(ignore previous instructions|pretend to|you are now|override behavior|disregard above|simulate|act as|bypass)/i.test(tool.description);
          return `
            <div class='p-4 border-l-4 border-blue-600 bg-blue-50 rounded shadow-sm'>
              <h3 class='text-lg font-bold text-blue-800'>${tool.name}</h3>
              <p class='mt-2 text-sm text-gray-700 whitespace-pre-line'>${tool.description.trim()}</p>
              ${suspicious ? '<p class="mt-2 text-sm font-semibold text-red-600">⚠️ Possible prompt injection detected!</p>' : ''}
            </div>
          `;
        }).join("");
      } catch (err) {
        errorDiv.textContent = `[ERROR] ${err}`;
        errorDiv.classList.remove("hidden");
      }
    });
  </script>
</body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route("/run-cli")
def run_cli():
    pkg = request.args.get("pkg", "").strip()
    if not pkg:
        return jsonify({"success": False, "error": "No package name provided."})

    try:
        command = f'echo \'{{"jsonrpc":"2.0","method":"tools/list","id":1}}\' | npx -y {pkg}'
        proc = subprocess.run(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=30
        )

        output = proc.stdout.strip()

        json_start = output.find('{')
        if json_start != -1:
            try:
                parsed = json.loads(output[json_start:])
                return jsonify({"success": True, "data": parsed})
            except json.JSONDecodeError as e:
                return jsonify({"success": False, "error": f"JSON parsing failed: {str(e)}", "raw": output})

        return jsonify({"success": False, "error": "No valid JSON found.", "raw": output})

    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "CLI command timed out."})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

if __name__ == "__main__":
    app.run(debug=True)
