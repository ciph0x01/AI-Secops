from flask import Flask, request, jsonify, render_template_string
from datetime import datetime
import os
import json
import codecs

app = Flask(__name__)
DATA_STORE = []
PAGE_SIZE = 20

# Bulletproof decoding function for all escaped string cases
def decode_escaped_strings(obj):
    if isinstance(obj, dict):
        return {k: decode_escaped_strings(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [decode_escaped_strings(i) for i in obj]
    elif isinstance(obj, str):
        try:
            # Decode escaped characters: \\n -> \n, \\uXXXX -> unicode, etc.
            decoded = codecs.decode(obj, 'unicode_escape')
            decoded = codecs.decode(decoded, 'unicode_escape')
            return decoded.replace('\r\n', '\n').replace('\r', '\n')
        except Exception:
            return obj
    return obj

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>MCP Exfiltration Dashboard</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #f5f7fa;
            margin: 0;
            padding: 20px;
        }
        h1 {
            color: #c0392b;
        }
        nav a {
            margin-right: 12px;
            text-decoration: none;
            color: #2c3e50;
            font-weight: bold;
        }
        nav a:hover {
            color: #e74c3c;
        }
        .filter-box input {
            padding: 10px;
            width: 320px;
            font-size: 14px;
            border: 1px solid #ccc;
            border-radius: 5px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            background: #fff;
            box-shadow: 0 2px 5px rgba(0,0,0,0.05);
        }
        th, td {
            padding: 12px;
            border-bottom: 1px solid #eee;
            text-align: left;
            vertical-align: top;
        }
        th {
            background-color: #f0f0f0;
        }
        pre.payload {
            margin: 0;
            background-color: #f9f9f9;
            border: 1px solid #ddd;
            padding: 10px;
            border-radius: 4px;
            max-height: 200px;
            overflow: auto;
            font-size: 13px;
            white-space: pre-wrap;
        }
        .expand-toggle {
            margin-top: 5px;
            display: inline-block;
            color: #3498db;
            cursor: pointer;
            font-size: 13px;
        }
        .pagination {
            margin-top: 20px;
            display: flex;
            justify-content: center;
            gap: 10px;
        }
        .pagination a {
            text-decoration: none;
            padding: 8px 14px;
            border: 1px solid #ccc;
            border-radius: 5px;
            background-color: #fff;
            color: #333;
        }
        .pagination a:hover {
            background-color: #f0f0f0;
        }
    </style>
    <script>
        function filterTable() {
            const input = document.getElementById('searchBox').value.toLowerCase();
            const rows = document.querySelectorAll('table tbody tr');
            rows.forEach(row => {
                const payload = row.querySelector('pre.payload').textContent.toLowerCase();
                row.style.display = payload.includes(input) ? '' : 'none';
            });
        }

        function toggleExpand(event) {
            const pre = event.target.previousElementSibling;
            if (pre.style.maxHeight === "800px") {
                pre.style.maxHeight = "200px";
                event.target.innerText = "Show more";
            } else {
                pre.style.maxHeight = "800px";
                event.target.innerText = "Show less";
            }
        }
    </script>
</head>
<body>
    <h1>📡 MCP Exfiltration Dashboard</h1>
    <nav>
        <a href="/">All</a>
        <a href="/workspace/data">Workspace</a>
        <a href="/system/data">System</a>
        <a href="/code/data">Code</a>
        <a href="/env/data">Environment</a>
        <a href="/dependencies/data">Dependencies</a>
        <a href="/workflows/data">Workflows</a>
    </nav>
    <div class="filter-box">
        <input type="text" id="searchBox" onkeyup="filterTable()" placeholder="🔍 Search payload..." />
    </div>
    <p><strong>Last updated:</strong> {{ now }}</p>
    <table>
        <thead>
            <tr>
                <th>Timestamp</th>
                <th>Endpoint</th>
                <th>Type</th>
                <th>Payload</th>
            </tr>
        </thead>
        <tbody>
        {% for row in data %}
        <tr>
            <td>{{ row.timestamp }}</td>
            <td>{{ row.endpoint }}</td>
            <td>{{ row.type }}</td>
            <td>
                <div>
                    <pre class="payload">{{ row.payload_pretty }}</pre>
                    <span class="expand-toggle" onclick="toggleExpand(event)">Show more</span>
                </div>
            </td>
        </tr>
        {% endfor %}
        </tbody>
    </table>
    <div class="pagination">
        {% if page > 1 %}<a href="{{ base_url }}?page={{ page - 1 }}">Previous</a>{% endif %}
        {% if has_more %}<a href="{{ base_url }}?page={{ page + 1 }}">Next</a>{% endif %}
    </div>
</body>
</html>
'''

def paginate(data, page):
    start = (page - 1) * PAGE_SIZE
    end = start + PAGE_SIZE
    return data[start:end], len(data) > end

@app.route("/", methods=["GET"])
def dashboard_all():
    page = int(request.args.get("page", 1))
    data, has_more = paginate(DATA_STORE, page)
    return render_template_string(
        HTML_TEMPLATE,
        data=data,
        now=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        page=page,
        has_more=has_more,
        base_url="/"
    )

@app.route("/<path:endpoint>", methods=["GET", "POST"])
def handle_exfil(endpoint):
    full_path = f"/{endpoint}"
    if request.method == "POST":
        try:
            raw_payload = request.get_json(force=True)
            timestamp = raw_payload.pop("timestamp", datetime.utcnow().isoformat())

            # Decode escaped characters
            payload = decode_escaped_strings(raw_payload)
            payload_pretty = json.dumps(payload, indent=2, ensure_ascii=False)

            DATA_STORE.append({
                "timestamp": timestamp,
                "endpoint": full_path,
                "type": payload.get("type", "unknown"),
                "payload": payload,
                "payload_pretty": payload_pretty
            })
            return jsonify({"status": "received"}), 200
        except Exception as e:
            return jsonify({"error": str(e)}), 400
    else:
        filtered = [item for item in DATA_STORE if item["endpoint"] == full_path]
        page = int(request.args.get("page", 1))
        data, has_more = paginate(filtered, page)
        return render_template_string(
            HTML_TEMPLATE,
            data=data,
            now=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            page=page,
            has_more=has_more,
            base_url=f"/{endpoint}"
        )

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    print(f"[+] MCP Exfiltration Server running on http://127.0.0.1:{port}")
    app.run(host="0.0.0.0", port=port)
