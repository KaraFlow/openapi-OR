#!/usr/bin/env python3
import argparse
import json
from pathlib import Path

COLORS = {
    "red": "\033[0;91m",
    "cyan": "\033[0;96m",
    "green": "\033[0;92m",
    "blue": "\033[0;94m",
    "purple": "\33[0;95m",
    "reset": ""
}

def colorize(item):
    if isinstance(item, tuple):
        text, color = item
        return f"{COLORS.get(color, '')}{text}\033[0m"

    return str(item)

HTTP_METHODS = {"get", "post", "put", "patch", "delete", "options", "head", "trace"}

SENSITIVE_KEYWORDS = [
    "admin", "user", "users", "role", "roles", "permission", "permissions",
    "setting", "settings", "auth", "token", "password", "log", "logs",
    "action-log", "action-logs", "delete", "bulk-delete"
]

IDOR_KEYWORDS = [
    "id", "user_id", "account_id", "role_id", "permission_id",
    "owner_id", "tenant_id", "post_id"
]

WRITE_METHODS = {"POST", "PUT", "PATCH"}
DESTRUCTIVE_METHODS = {"DELETE"}

SMART_PAYLOADS = {
    "integer": ["ids.txt", "numbers.txt"],
    "number": ["numbers.txt"],
    "string": ["strings.txt"],
    "boolean": ["booleans.txt"],
    "unknown": ["generic.txt"]
}

def load_json(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"[!] Error loading file: {e}")
        exit(1)


def schema_type(schema):
    if not schema:
        return "unknown"

    if "$ref" in schema:
        return schema["$ref"]

    t = schema.get("type", "unknown")

    if isinstance(t, list):
        return "|".join(t)

    if t == "array":
        return f"array[{schema_type(schema.get('items', {}))}]"

    return t


def extract_data(data):
    result = {
        "info": {
            "title": data.get("info", {}).get("title", "Unknown"),
            "version": data.get("info", {}).get("version", "unknown"),
            "openapi": data.get("openapi", "unknown"),
        },
        "paths": []
    }

    for path, path_item in data.get("paths", {}).items():
        for method, operation in path_item.items():
            if method.lower() not in HTTP_METHODS:
                continue

            entry = {
                "path": path,
                "method": method.upper(),
                "summary": operation.get("summary", ""),
                "operationId": operation.get("operationId", ""),
                "tags": operation.get("tags", []),
                "parameters": [],
                "requestBody": None,
                "responses": list(operation.get("responses", {}).keys())
            }

            # Parameters
            for p in operation.get("parameters", []):
                entry["parameters"].append({
                    "name": p.get("name"),
                    "in": p.get("in"),
                    "required": p.get("required", False),
                    "type": schema_type(p.get("schema", {}))
                })

            # Request body
            rb = operation.get("requestBody")
            if rb:
                entry["requestBody"] = {
                    "required": rb.get("required", False),
                    "content_types": list(rb.get("content", {}).keys())
                }

            result["paths"].append(entry)

    return result


def render_text(data):
    lines = []
    lines.append("")
    lines.append((f"[+] API Title: {data['info']['title']}", "green"))
    lines.append((f"[+] API Version: {data['info']['version']}", "green"))
    lines.append((f"[+] OpenAPI Version: {data['info']['openapi']}", "green"))
    lines.append((f"[+] Number of paths: {len(data['paths'])}", "green"))
    lines.append("")
    lines.append(("[+] Listing paths, methods and parameters", "cyan"))
    lines.append("")

    for p in data["paths"]:
        lines.append((f"\npath: {p['path']}", "red"))
        lines.append(f"method: {p['method']}")
        lines.append(f"summary: {p['summary']}")
        lines.append(f"operationId: {p['operationId']}")
        lines.append(f"tags: {', '.join(p['tags']) or 'none'}")

        if p["parameters"]:
            lines.append("  parameters:")
            for param in p["parameters"]:
                lines.append(f"    - name: {param['name']}")
                lines.append(f"      in: {param['in']}")
                lines.append(f"      required: {param['required']}")
                lines.append(f"      type: {param['type']}")
        else:
            lines.append("  parameters: none")

        if p["requestBody"]:
            rb = p["requestBody"]
            lines.append("  requestBody: yes")
            lines.append(f"    required: {rb['required']}")
            lines.append(f"    content-types: {', '.join(rb['content_types'])}")
        else:
            lines.append("  requestBody: none")

        lines.append(f"  responses: {', '.join(p['responses'])}")

    return "\n".join(colorize(line) for line in lines)


def save_output(content, path, append=False):
    mode = "a" if append else "w"
    with open(path, mode, encoding="utf-8") as f:
        f.write(content + "\n")

def risk_level(score):
    if score >= 8:
        return "HIGH"
    if score >= 5:
        return "MEDIUM"
    if score >= 2:
        return "LOW"
    return "INFO"


def audit_endpoint(endpoint):
    score = 0
    reasons = []

    path = endpoint["path"].lower()
    method = endpoint["method"]
    responses = endpoint.get("responses", [])
    params = endpoint.get("parameters", [])
    tags = [t.lower() for t in endpoint.get("tags", [])]

    # Destructive or write methods
    if method in DESTRUCTIVE_METHODS:
        score += 3
        reasons.append("destructive HTTP method")

    if method in WRITE_METHODS:
        score += 2
        reasons.append("write-capable HTTP method")

    # Path parameters / IDOR candidates
    path_params = [p for p in params if p.get("in") == "path"]

    if path_params:
        score += 2
        reasons.append("uses path parameter")

    for p in path_params:
        name = str(p.get("name", "")).lower()
        if name in IDOR_KEYWORDS or name.endswith("_id"):
            score += 2
            reasons.append(f"IDOR/BOLA candidate parameter: {name}")

    # Sensitive path/tag names
    combined = path + " " + " ".join(tags)

    for keyword in SENSITIVE_KEYWORDS:
        if keyword in combined:
            score += 1
            reasons.append(f"sensitive keyword: {keyword}")
            break

    # Request body increases attack surface
    if endpoint.get("requestBody"):
        score += 1
        reasons.append("has request body")

    # Missing auth-like response codes
    if "401" not in responses and "403" not in responses:
        score += 2
        reasons.append("no documented 401/403 response")

    # Bulk operations
    if "bulk" in path:
        score += 2
        reasons.append("bulk operation")

    # Admin/internal style paths
    if any(x in path for x in ["/admin", "/internal", "/debug", "/config"]):
        score += 3
        reasons.append("admin/internal-style path")

    return {
        "path": endpoint["path"],
        "method": method,
        "score": score,
        "risk": risk_level(score),
        "reasons": reasons
    }

def run_audit(data):
    findings = []

    for endpoint in data["paths"]:
        finding = audit_endpoint(endpoint)

        if finding["score"] > 0:
            findings.append(finding)

    findings.sort(key=lambda x: x["score"], reverse=True)

    return findings

def render_audit(findings):
    lines = []

    lines.append("")
    lines.append(("[+] OpenAPI Risk Audit", "cyan"))
    lines.append("")

    if not findings:
        lines.append(("[+] No notable risks detected.", "green"))
        return "\n".join(colorize(line) for line in lines)

    for f in findings:
        lines.append("")
        lines.append((f"[{f['risk']}] {f['method']} {f['path']}", "red"))
        lines.append((f"score: {f['score']}", "red"))
        lines.append((f"reasons:", "blue"))

        for reason in f["reasons"]:
            lines.append(f"  - {reason}")

    return "\n".join(colorize(line) for line in lines)

def parse_profiles(profiles_str):
    if not profiles_str:
        return []
    return [p.strip().lower() for p in profiles_str.split(",")]

def generate_idor_attacks(endpoint):
    attacks = []

    for p in endpoint.get("parameters", []):
        if p.get("in") == "path":
            name = str(p.get("name", "")).lower()

            if name in IDOR_KEYWORDS or name.endswith("_id"):
                attacks.append(f"Try ID enumeration on {name}: 1,2,3,999,-1")
                attacks.append(f"Test horizontal access on {endpoint['path']}")

    return attacks

SQLI_PAYLOADS = [
    "' OR 1=1 --",
    "' OR 'a'='a",
    "\" OR \"a\"=\"a",
    "'; DROP TABLE users; --"
]

def generate_sqli_attacks(endpoint):
    attacks = []

    for p in endpoint.get("parameters", []):
        if p.get("in") in ["query", "path"]:
            attacks.append(f"SQLi test on param '{p['name']}' with payloads: {SQLI_PAYLOADS}")

    if endpoint.get("requestBody"):
        attacks.append("SQLi test in request body fields")

    return attacks

def generate_auth_attacks(endpoint):
    attacks = []

    responses = endpoint.get("responses", [])

    if "401" in responses or "403" in responses:
        attacks.append("Test without authentication")
        attacks.append("Test with invalid token")
        attacks.append("Test with low-privilege token")

    else:
        attacks.append("Endpoint might be missing auth protection")

    return attacks

def generate_attacks(data, profiles):
    results = []

    for endpoint in data["paths"]:
        entry = {
            "path": endpoint["path"],
            "method": endpoint["method"],
            "attacks": []
        }

        if "idor" in profiles:
            entry["attacks"] += generate_idor_attacks(endpoint)

        if "sqli" in profiles:
            entry["attacks"] += generate_sqli_attacks(endpoint)

        if "auth" in profiles:
            entry["attacks"] += generate_auth_attacks(endpoint)

        if entry["attacks"]:
            results.append(entry)

    return results

def render_attacks(attacks):
    lines = []

    lines.append("")
    lines.append(("[+] Attack Suggestions", "cyan"))
    lines.append("")

    if not attacks:
        lines.append(("[+] No attacks generated.", "cyan"))
        return "\n".join(colorize(line) for line in lines)

    for a in attacks:
        lines.append("")
        lines.append((f"{a['method']} {a['path']}", "red"))

        for atk in a["attacks"]:
            lines.append(f"  - {atk}")

    return "\n".join(colorize(line) for line in lines)

def normalize_domain(domain):
    domain = domain.rstrip("/")

    if not domain.startswith(("http://", "https://")):
        domain = "https://" + domain

    return domain

def payload_wordlists_for_type(param_type):
    return SMART_PAYLOADS.get(param_type, ["generic.txt"])

def replace_path_param(path, param_name):
    return path.replace("{" + param_name + "}", "FUZZ")

def generate_ffuf(data, domain):
    domain = normalize_domain(domain)
    commands = []

    for endpoint in data["paths"]:
        path = endpoint["path"]
        method = endpoint["method"]

        for param in endpoint.get("parameters", []):
            name = param.get("name")
            location = param.get("in")
            param_type = param.get("type", "unknown")
            wordlists = payload_wordlists_for_type(param_type)

            if not name:
                continue

            if location == "path":
                fuzzed_path = replace_path_param(path, name)
                url = domain + fuzzed_path

            elif location == "query":
                clean_path = path

                # Replace any path parameters with safe placeholder values
                for p in endpoint.get("parameters", []):
                    if p.get("in") == "path" and p.get("name"):
                        clean_path = replace_path_param(clean_path, p.get("name")).replace("FUZZ", "1")

                separator = "&" if "?" in clean_path else "?"
                url = domain + clean_path + f"{separator}{name}=FUZZ"

            else:
                continue

            for wl in wordlists:
                commands.append({
                    "method": method,
                    "path": path,
                    "parameter": name,
                    "location": location,
                    "type": param_type,
                    "wordlist": wl,
                    "command": f"ffuf -u '{url}' -w {wl} -X {method}"
                })

    return commands

def render_ffuf(commands):
    lines = []

    lines.append("")
    lines.append(("[+] ffuf Commands", "cyan"))
    lines.append("")

    if not commands:
        lines.append(("[+] No ffuf commands generated.", "cyan"))
        return "\n".join(colorize(line) for line in lines)

    for item in commands:
        lines.append("")
        lines.append((f"{item['method']} {item['path']}", "red"))
        lines.append(f"parameter: {item['parameter']}")
        lines.append(f"location: {item['location']}")
        lines.append(f"type: {item['type']}")
        lines.append(f"wordlist: {item['wordlist']}")
        lines.append((f"command: {item['command']}", "purple"))

    return "\n".join(colorize(line) for line in lines)

def main():
    parser = argparse.ArgumentParser(description="OpenAPI Offensive Roadmap")

    parser.add_argument("file", help="OpenAPI JSON file")
    parser.add_argument("-o", "--output", help="Output file")
    parser.add_argument("--format", choices=["text", "json"], default="text")
    parser.add_argument("--append", action="store_true", help="Append instead of overwrite")
    parser.add_argument(
        "--profiles",
        help="Generate attack suggestions. Example: --profiles idor,sqli,auth"
    )
    parser.add_argument(
        "--ffuf",
        help="Generate context-aware ffuf commands for an in-scope base URL"
    )

    args = parser.parse_args()

    raw = load_json(args.file)
    extracted = extract_data(raw)

    findings = run_audit(extracted)

    profiles = parse_profiles(args.profiles) if args.profiles else []

    attacks = []
    if profiles:
        attacks = generate_attacks(extracted, profiles)

    ffuf_commands = []
    if args.ffuf:
        ffuf_commands = generate_ffuf(extracted, args.ffuf)

    if args.format == "json":
        output_data = {
            "extraction": extracted,
            "audit": findings
        }

        if profiles:
            output_data["attacks"] = attacks

        if args.ffuf:
            output_data["ffuf"] = ffuf_commands

        output = json.dumps(output_data, indent=2)

    else:
        output = render_text(extracted)
        output += "\n\n"
        output += render_audit(findings)

        if profiles:
            output += "\n\n"
            output += render_attacks(attacks)

        if args.ffuf:
            output += "\n\n"
            output += render_ffuf(ffuf_commands)

    if args.output:
        save_output(output, args.output, args.append)
        print(f"[+] Output saved to: {args.output}")
    else:
        print(output)


if __name__ == "__main__":
    main()
