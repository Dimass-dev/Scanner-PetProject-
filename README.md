# Multi-Scanner & Risk Assessment Platform

[![CI](https://github.com/your-org/scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/your-org/scanner/actions/workflows/ci.yml)

A local security assessment tool for Windows PE files (`.exe`, `.dll`, `.sys`), ZIP archives, and explicitly allowlisted web services.

## ⚠️ Important Disclaimer

**This is not an antivirus or a complete penetration-testing system.** PE analysis is static. Web scanning currently performs a bounded passive baseline, reviews an optional OpenAPI 3.x JSON document, and offers a separate low-volume test of login throttling. It does not prove that an application is secure or replace source review, professional security testing, or infrastructure review.

Use this tool as part of a defense-in-depth strategy, not as a replacement for proper antivirus solutions.

## Features

- **Static PE Analysis**: Parse and analyze PE/COFF structures without loading files into memory
- **Security Mitigations**: Check for ASLR, DEP, CFG, SafeSEH, and High Entropy VA
- **Risk Assessment**: Automated scoring based on 30+ security rules
- **Import Analysis**: Detect suspicious API usage (process injection, networking, persistence)
- **Entropy Detection**: Identify packed or encrypted sections
- **Code Signing**: Verify Authenticode digests cross-platform, with a `WinVerifyTrust` cross-check on Windows
- **Archive Support**: Safe ZIP extraction with Zip Slip and Zip Bomb protection, plus per-file archive navigation in the UI
- **REST API**: JSON-based API for integration
- **Web UI**: Interactive interface for file analysis
- **Web Service Baseline**: Bounded same-origin HTTP(S) checks for response headers, cookies, HTTP status and basic exposure
- **OpenAPI Review**: Local review of an OpenAPI 3.x JSON file; in the opt-in active profile, bounded GET responses are checked against declared status codes and a supported JSON Schema subset
- **Login Throttling Check**: Optional maximum of five failed JSON login attempts using generated random passwords and a dedicated test account
- **Load Test Script**: Creates a bounded read-only k6 script (maximum 5 requests/sec, 30 seconds, and 5 VUs); the scanner does not run it

## Architecture

```
┌─────────────────────── UI (React 19 + TypeScript) ──────────────────────┐
│  Upload · Risk Banner · Findings · Mitigations · Entropy · Imports      │
└──────────────────────────────┬───────────────────────────────────────────┘
                               │ REST API
┌──────────────────────── Server (ASP.NET Core) ──────────────────────────┐
│  Endpoints · Services · Rate Limiting · Security Limits                 │
└──────────────────────────────┬───────────────────────────────────────────┘
                               │ Scan Coordinator
┌──────────────────────────── Core (.NET 10) ──────────────────────────────┐
│  PE Parser · Rules Engine · Risk Assessment · Signature Verification     │
└───────────────────────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites

- .NET 10 SDK
- Node.js 20+ (for UI)

### Building

```bash
# Backend
dotnet restore
dotnet build

# Frontend
cd UI
npm install
npm run build
```

### Running

```bash
# Console scanner
dotnet run --project Scanner.Console -- path/to/file.exe

# Web API (terminal 1)
dotnet run --project Server/Server.csproj --launch-profile http

# Web UI (terminal 2)
cd UI
npm install
npm run dev
# Open http://localhost:5173
```

The UI proxies API requests to `http://localhost:5290`. Health check: `http://localhost:5290/api/scan/health`.

### Web Target Scope

The web scanner rejects origins not listed in `WebScanner:AllowedOrigins` in `Server/appsettings.json`. The defaults are loopback-only. To scan a staging service, add its exact origin (scheme, hostname and port), for example `https://staging.example.test`; do not add broad wildcard domains. DNS results are checked again at connection time, automatic redirects are disabled, and only same-origin redirects are followed.

Passive baseline sends bounded GET requests and does not submit forms. The optional limited-active profile uses a very small budget for database-error and inert HTML-reflection signals and may probe documented GET routes without credentials; it does not execute scripts or extract data. Even GET routes can have side effects, so use staging. The login-throttling panel sends up to five failed JSON requests to the supplied path using a dedicated test account; it can lock that account. The load-test panel only generates a separate k6 script. The scan API itself accepts requests only from the local machine. Run active or load checks against a local/staging target you own or have explicit permission to test.

### Testing

```bash
# All tests
dotnet test

# Specific project
dotnet test Test/Test.csproj
```

## Security Limits

The platform enforces strict limits to prevent abuse and resource exhaustion:

| Limit | Default Value |
|-------|---------------|
| Maximum file size | 100 MB |
| Maximum archive size | 200 MB |
| Maximum uncompressed size | 1 GB |
| Maximum archive entries | 500 |
| Maximum compression ratio | 100:1 |
| Maximum scan time | 120 seconds |
| API rate limit | 10 requests / 60 seconds per client |
| Maximum OpenAPI document | 1 MiB |
| Maximum login-throttling attempts | 5 |
| Maximum certificate table | 16 MiB |
| Maximum imported libraries | 4,096 |
| Maximum imported functions | 200,000 |
| Maximum certificate chain errors retained | 16 |

Server limits are configurable via `appsettings.json`. Parser safety caps (certificate size, import counts) are fixed in `Core` to keep untrusted input bounded. The scan API only accepts loopback clients.

## Risk Scoring

Files are scored based on findings across multiple categories:

- **Critical** (50 pts): RWX sections, process injection patterns
- **High** (15 pts): Missing ASLR/DEP, suspicious entry points, packed executables
- **Medium** (5 pts): Networking APIs, persistence mechanisms, missing CFG
- **Low** (1 pt): Missing signatures, unusual timestamps
- **Info** (0 pts): Informational findings

Final risk level is determined by the highest severity finding and cumulative score.

## Project Structure

```
Scanner(PetProject)/
├── Core/                      # PE parsing and analysis engine
│   ├── Analysis/             # PeImageParser, PeFileReader
│   ├── PE/, Sections/, ImpParser/
│   │                         # Header, Section, Import, Delay-import parsers
│   ├── Parsing/              # Entropy, overlay, certificate, Authenticode
│   ├── Rules/                # IRule interface, engine, built-in rules, catalogs
│   ├── Risk/                 # RiskAssessmentEngine
│   └── Scanning/             # IScanModule, ScanCoordinator
├── Server/                    # REST API (ASP.NET Core)
│   ├── Program.cs            # File, archive, web, and health endpoints
│   ├── Services/             # FileScanService, ArchiveService, TempStorage
│   ├── Options/              # ScannerOptions configuration
│   └── DTOs/                 # API contracts
├── Scanner.Console/           # CLI tool
├── Scanner.Desktop/           # WPF desktop client
├── Test/                      # Unit and API integration tests
└── UI/                        # React frontend
    ├── src/components/       # Upload, findings, artifacts, archive browser
    └── src/hooks/            # React hooks and API calls
```

## API Endpoints

### Scan Single File
```http
POST /api/scan/file
Content-Type: multipart/form-data

file: <binary>
```

### Scan Archive
```http
POST /api/scan/archive
Content-Type: multipart/form-data

file: <binary>
```

### Health Check
```http
GET /api/scan/health
POST /api/scan/web
POST /api/scan/web/auth-rate-limit
```

`POST /api/scan/web` accepts JSON containing `targetUrl` and optional `openApiDocument` (maximum 1 MiB). `POST /api/scan/web/auth-rate-limit` requires explicit confirmation of a dedicated test account and is capped by `WebScanner:MaxAuthProbeAttempts` (default 5).

See the generated API specification at `/openapi/v1.json` in Development.

## Development

### Code Style

- Follow `.editorconfig` conventions
- Run `dotnet format` before committing
- Keep warnings enabled (`TreatWarningsAsErrors`)

### Testing Strategy

- **Unit tests**: Synthetic PE files, signature fixtures, rule and risk coverage
- **Integration tests**: `WebApplicationFactory` for file, archive, health, local-only, and error paths
- **Security tests**: Zip Slip, oversized entries/archives, certificate bounds, import budgets
- **Reliability tests**: client cancellation vs. scan timeout
- **Cross-platform**: CI runs on Ubuntu and Windows

### Contributing

1. Fork the repository
2. Create a feature branch
3. Run tests: `dotnet test && cd UI && npm run lint`
4. Submit a pull request

## Roadmap

- [x] Phase 0: Project hygiene, build settings, and CI
- [x] Phase 1: Core parsing layer (`PeImage`, single-open reader, cancellation)
- [x] Phase 2: Rules engine, risk assessment, mitigations, imports, entropy
- [x] Phase 3: Server API, bounded ZIP handling, local-only scan API
- [x] Phase 4: Web UI, desktop client, React and WPF package tabs
- [x] Phase 5: Hardening — Authenticode digest verification, certificate/import caps, timeout/cancellation handling
- [x] Phase 6: Test and UX polish — API integration tests, structured artifacts, archive browser, accessibility
- [ ] Future: SSE/background progress, JSON report export, scan history, streaming ZIP parsing

## License

MIT License - see LICENSE file for details.

## Acknowledgments

This project uses static analysis techniques and does not execute or emulate malware. Analysis patterns are based on publicly documented PE/COFF specifications and common malware characteristics.

---

**Remember**: This tool provides structural analysis only. Always use proper malware sandboxing and antivirus solutions for comprehensive threat detection.
