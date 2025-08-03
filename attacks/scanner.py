# scanner_cli.py

import os
import sys
import argparse
import openai
import requests
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.progress import Progress, SpinnerColumn, TextColumn
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak, Preformatted
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER

console = Console()

# === Configuration ===
MODEL = "gpt-4o-mini"
SYSTEM_PROMPT = """
You are a security expert AI assistant specializing in static code analysis.
For the provided source code, identify technical security vulnerabilities with detailed explanation,
and generate working exploit payloads or proof-of-concept code snippets specifically for those vulnerabilities.
Respond ONLY with JSON in this exact format:

{
  "vulnerabilities": [
    {
      "type": "Vulnerability Type",
      "severity": "Critical|High|Medium|Low",
      "file": "filename.py",
      "line": line_number,
      "description": "Technical explanation of the vulnerability",
      "payload": "Exploit payload or injection code snippet",
      "exploit": "Working proof-of-concept exploit code or commands",
      "code_snippet": "The vulnerable code snippet",
      "cwe": "CWE-XXX (optional)",
      "cve": "CVE-YYYY-XXXX (optional)"
    },
    ...
  ]
}
"""

LOGIC_GUIDANCE = """
Before scanning for vulnerabilities, thoroughly analyze and understand the full logical flow of this code.

- Identify the purpose of each function and how they interact
- Determine input entry points and whether they reach security-sensitive operations
- Understand authentication, authorization, and business logic paths
- Only after understanding the logic, identify vulnerabilities and generate working exploits

Do not skip logic comprehension steps. If a function appears to process user input, explain how it flows into the vulnerable area.
"""

def read_code_file(path):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return f.read()

def chunk_code(code, max_tokens):
    import tiktoken
    enc = tiktoken.get_encoding("cl100k_base")
    tokens = enc.encode(code)
    chunks = []
    for i in range(0, len(tokens), max_tokens):
        chunk_tokens = tokens[i:i+max_tokens]
        chunk_text = enc.decode(chunk_tokens)
        chunks.append(chunk_text)
    return chunks

def call_openai_api(prompt, model=MODEL, max_tokens=1500):
    try:
        response = openai.ChatCompletion.create(
            model=model,
            messages=prompt,
            temperature=0,
            max_tokens=max_tokens,
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        console.print(f"[red]OpenAI API call failed: {e}[/]")
        sys.exit(1)

def call_ollama_api(prompt):
    try:
        response = requests.post(
            "http://localhost:11434/api/chat",
            json={"model": "codellama", "messages": prompt, "stream": False},
            timeout=300
        )
        response.raise_for_status()
        return response.json()["message"]["content"].strip()
    except Exception as e:
        console.print(f"[red]Ollama call failed: {e}[/]")
        sys.exit(1)

def prepare_prompt_for_chunk(code_chunk, filename):
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": f"{LOGIC_GUIDANCE}\n\nAnalyze this code from '{filename}':\n\n```\n{code_chunk}\n```"}
    ]

def parse_openai_response(response_text):
    import json
    try:
        if response_text.startswith("```json"):
            response_text = response_text[len("```json"):].rstrip("```").strip()
        elif response_text.startswith("```"):
            response_text = response_text.strip("```").strip()
        return json.loads(response_text)
    except Exception as e:
        console.print(f"[red]Failed to parse JSON: {e}[/]")
        console.print(response_text)
        sys.exit(1)


def print_vulnerability(vuln, index):
    severity_colors = {"Critical": "bold red", "High": "red", "Medium": "yellow", "Low": "green"}
    severity = vuln.get("severity", "N/A")
    style = severity_colors.get(severity, "white")
    console.rule(f"[bold cyan]Vulnerability #{index}[/]")
    console.print(f"[bold]{vuln.get('type')}[/] [{style}]{severity}[/]")
    console.print(f"File: {vuln.get('file')} | Line: {vuln.get('line')}")
    console.print(f"[italic]{vuln.get('description')}[/]")
    if vuln.get("code_snippet"):
        console.print("[bold]Code:[/]")
        console.print(Syntax(vuln["code_snippet"], "python", theme="monokai"))
    if vuln.get("payload"):
        console.print("[bold]Payload:[/]")
        console.print(Syntax(vuln["payload"], "bash"))
    if vuln.get("exploit"):
        console.print("[bold]Exploit:[/]")
        console.print(Syntax(vuln["exploit"], "python"))

def print_report(vulnerabilities, filename):
    if not vulnerabilities:
        console.print(f"[green]✅ No vulnerabilities found in {filename}[/]")
        return
    console.print(Panel.fit(f"[bold red]{len(vulnerabilities)} vulnerabilities found in {filename}", style="bold red"))
    for i, vuln in enumerate(vulnerabilities, 1):
        print_vulnerability(vuln, i)

def generate_pdf_report(vulns, filename, output_path):
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="CenterTitle", alignment=TA_CENTER, fontSize=20, spaceAfter=20))
    styles.add(ParagraphStyle(name="Heading1", fontSize=16, spaceAfter=12))
    styles.add(ParagraphStyle(name="CodeBlock", fontName="Courier", fontSize=8, backColor=colors.whitesmoke, leading=10))
    doc = SimpleDocTemplate(output_path, pagesize=LETTER, rightMargin=72, leftMargin=72, topMargin=72, bottomMargin=72)
    elements = [Paragraph("Secure Code Analysis Report", styles["CenterTitle"]), Spacer(1, 12)]

    if not vulns:
        elements.append(Paragraph("No vulnerabilities found.", styles["Heading1"]))
    else:
        for i, v in enumerate(vulns, 1):
            elements.append(Paragraph(f"{i}. {v.get('type')} [{v.get('severity')}]", styles["Heading1"]))

            elements.append(Paragraph(f"File: {v.get('file')} | Line: {v.get('line')}", styles["Normal"]))
            elements.append(Spacer(1, 6))
            elements.append(Paragraph(v.get("description", ""), styles["Normal"]))
            for label, content in [("Code", v.get("code_snippet")), ("Payload", v.get("payload")), ("Exploit", v.get("exploit"))]:
                if content:
                    elements.append(Paragraph(f"<b>{label}:</b>", styles["Normal"]))
                    elements.append(Preformatted(content, styles["CodeBlock"]))
                    elements.append(Spacer(1, 6))
            elements.append(PageBreak())
    doc.build(elements)

def scan_file(filepath, api_key, provider, generate_pdf, max_tokens):
    code = read_code_file(filepath)
    code_chunks = chunk_code(code)
    all_vulns = []
    for idx, chunk in enumerate(code_chunks, 1):
        console.print(f"[blue]Analyzing chunk {idx}/{len(code_chunks)} of {filepath}...[/]")
        prompt = prepare_prompt_for_chunk(chunk, os.path.basename(filepath))
        if provider == "ollama":
            response = call_ollama_api(prompt)
        else:
            openai.api_key = api_key
            response = call_openai_api(prompt, max_tokens=max_tokens)
        data = parse_openai_response(response)
        all_vulns.extend(data.get("vulnerabilities", []))
    print_report(all_vulns, filepath)
    if generate_pdf:
        pdf_path = os.path.splitext(filepath)[0] + "_scan_report.pdf"
        generate_pdf_report(all_vulns, filepath, pdf_path)
        console.print(f"[green]PDF saved to {pdf_path}[/]")

def scan_path(path, api_key, provider, generate_pdf, max_tokens):
    if os.path.isfile(path):
        scan_file(path, api_key, provider, generate_pdf, max_tokens)
    elif os.path.isdir(path):
        for root, _, files in os.walk(path):
            for f in files:
                if f.endswith(".py"):
                    scan_file(os.path.join(root, f), api_key, provider, generate_pdf, max_tokens)
    else:
        console.print(f"[red]Invalid path: {path}[/]")

def main():
    parser = argparse.ArgumentParser(description="Secure Code Review CLI with OpenAI or Ollama")
    parser.add_argument("path", help="Path to file or directory to scan")
    parser.add_argument("--api-key", help="OpenAI API key (optional if using Ollama)")
    parser.add_argument("--provider", choices=["openai", "ollama"], default="openai", help="Model provider")
    parser.add_argument("--pdf-report", action="store_true", help="Generate PDF report")
    parser.add_argument("--max-tokens", type=int, default=1500, help="Max tokens for OpenAI completion (ignored for Ollama)")
    args = parser.parse_args()

    if args.provider == "openai" and not (args.api_key or os.getenv("OPENAI_API_KEY")):
        console.print("[red]Missing OpenAI API key. Use --api-key or set OPENAI_API_KEY env var.[/]")
        sys.exit(1)

    scan_path(args.path, args.api_key or os.getenv("OPENAI_API_KEY"), args.provider, args.pdf_report, args.max_tokens)

if __name__ == "__main__":
    main()
