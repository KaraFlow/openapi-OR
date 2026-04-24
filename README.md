### OpenAPI Offensive Roadmap

A lightweight offensive security tool that parses OpenAPI (Swagger) specifications and turns them into actionable insights for penetration testing.

Instead of blindly fuzzing APIs, this tool focuses on understanding the attack surface and generating targeted attack strategies.

---

### Features

1) API Extraction

- Parses OpenAPI JSON files
- Lists:
  - Paths
  - Methods
  - Parameters (type, location, required)
  - Request bodies
  - Response codes

2) Risk Scoring Engine

- Each endpoint is analyzed and assigned a risk score based on:
  - HTTP method (write / destructive)
  - Presence of ID-based parameters (IDOR/BOLA)
  - Sensitive keywords ("user", "admin", "role", etc.)
  - Missing authentication responses ("401", "403")
  - Request body exposure
  - Bulk operations
  - Internal/admin paths

```
Example:

[HIGH] DELETE /v1/users/{id}
score: 10
reasons:
  - destructive HTTP method
  - uses path parameter
  - IDOR/BOLA candidate parameter: id
  - sensitive keyword: user
```

3) Attack Profiles

- Generate targeted attack suggestions based on endpoint structure.

- Supported profiles:
  - "idor" → ID enumeration & access control testing
  - "sqli" → SQL injection testing points
  - "auth" → Authentication / authorization testing

```
Example:

GET /v1/users/{id}
  - Try ID enumeration on id: 1,2,3,999,-1
  - Test horizontal access on /v1/users/{id}
  - SQLi test on param 'id' with payloads: [...]
  - Test without authentication
```

4) Smart Fuzzing

- Generate context-aware ffuf commands instead of generic "FUZZ".
- Uses parameter types to select payload wordlists
- Supports:
  - Path parameters
  - Query parameters
- Automatically builds valid URLs

```
Example:

GET /v1/users/{id}
parameter: id
type: integer
wordlist: numbers.txt

ffuf -u 'https://target.com/v1/users/FUZZ' -w numbers.txt -X GET
```

---

### Installation

```
git clone https://github.com/KaraFlow/openapi-OR.git
cd openapi-OR
python3 main.py --help
```

---

### Usage

```
Basic analysis
python3 main.py api.json

Save output
python3 main.py api.json -o report.txt

JSON output
python3 main.py api.json --format json

Attack profiles
python3 main.py api.json --profiles idor,sqli,auth

Smart fuzzing
python3 main.py api.json --ffuf https://target.com

Combined
python3 main.py api.json \
  --profiles idor,auth \
  --ffuf https://target.com \
  -o full_report.txt
```

---

### Wordlists

Place these files in the same directory as the script:
```
- "numbers.txt"
- "strings.txt"
- "booleans.txt"
- "generic.txt"
```

---

### Design Philosophy

Most OpenAPI tools focus on:

- Random fuzzing
- Payload mutation
- Request replay

This tool focuses on:

- Attack surface understanding
- Risk prioritization
- Context-aware attack generation
