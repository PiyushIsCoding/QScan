# QScan — Quantum-Readiness CBOM Analyzer

> Smart India Hackathon prototype (PS 26164): discover cryptographic assets, build a CycloneDX CBOM, assess quantum risk with Mosca's inequality, recommend PQC/hybrid alternatives, and plan a dependency-aware migration.

QScan is not just a "find RSA" scanner. Its goal is to answer: **what should the organization migrate first, to what, and why?**

```
Discover  →  Normalize  →  CBOM  →  Quantum risk (Mosca)  →  PQC recommendation  →  Migration plan
```

---

## Features

**Discovery**
- Source scanning for Python, JavaScript/TypeScript, Java and Go (pattern-based, with lightweight constant tracking, e.g. a key size set in a variable is resolved)
- Dependency manifests: `requirements.txt`, `package.json`, `pom.xml`, `go.mod`, `Cargo.toml`, `pyproject.toml`, `setup.py`, `setup.cfg`, `Pipfile`
- X.509 certificates (key type, size, subject/issuer, validity period) and PEM private keys (classified by type; **contents are never stored**), plus keystore flagging (`.p12`, `.pfx`, `.jks`)
- Protocol configuration: nginx `ssl_protocols` / `ssl_ciphers`, SSH `KexAlgorithms` / `HostKeyAlgorithms`
- Cloud KMS (AWS, Azure, Google) and HSM / PKCS#11 references
- Every finding carries an evidence trail and a confidence score

**Risk and recommendations**
- Configurable weighted risk score plus a Mosca check per asset
- Purpose-aware PQC recommendations (ML-KEM, ML-DSA, SLH-DSA, hybrid vs. direct) with key/signature sizes
- Tests, docs and examples are scored separately from production code

**Planning and output**
- Service dependency graph from `docker-compose.yml` (`depends_on`) or manual input
- Migration plan ordered by severity phase, then by how many services depend on the asset's service
- What-if slider: projected readiness after migrating the top N items
- CycloneDX 1.6 CBOM export (JSON)
- React dashboard: Overview, Crypto Inventory, Risk & Mosca, Migration Planner

---

## Repository layout

```
qscan/
├── core.py            # scanner, normalization, risk engine, recommender, planner, CBOM export
├── requirements.txt   # Python dependencies
├── app.py             # FastAPI backend (serves the built React app if present)
├── index.html         # legacy single-file dashboard (fallback)
├── demo_repo.zip      # demo project with planted crypto usage
└── frontend/          # React + Vite dashboard
    ├── index.html
    ├── package.json
    ├── vite.config.js
    └── src/
        ├── main.jsx
        ├── App.jsx
        ├── views.jsx
        └── styles.css
```

---

## Setup

**Requirements:** Python 3.10+, Node.js 18+

### Backend

```bash
python -m venv .venv
# activate: Windows PowerShell  .venv\Scripts\Activate.ps1
#           Windows cmd         .venv\Scripts\activate
#           Mac/Linux           source .venv/bin/activate
pip install -r requirements.txt
uvicorn app:app --reload          # http://localhost:8000
```

`cryptography` is optional but needed to parse certificates and private keys; without it those files are only detected by header.

### Frontend (development)

In a second terminal:

```bash
cd frontend
npm install
npm run dev                       # http://localhost:5173
```

Vite proxies `/api` to `localhost:8000`, so the backend must be running.

### Production-style single server

```bash
cd frontend && npm run build && cd ..
uvicorn app:app                   # serves the UI and API on http://localhost:8000
```

If `frontend/dist` does not exist, `app.py` serves the legacy `index.html` dashboard instead.

---

## Usage

1. Open the dashboard and choose a repository **ZIP** (GitHub "Download ZIP" works; the single root folder is stripped automatically).
2. Set the context. Code cannot reveal how sensitive the data is, so these are user-supplied:
   - sensitivity, criticality, exposure (internal / internet-facing)
   - data lifetime (years) and migration time (years)
   - quantum threat horizon: conservative 10y, moderate 15y, aggressive 20y
3. Optionally add per-service overrides and manual dependencies as JSON:

```json
{
  "payment-service": { "sensitivity": "critical" },
  "deps": { "payment-service": ["auth-service"] }
}
```

   A service is the top-level folder of the project. `deps` means "the key depends on the listed services".
4. Click **Scan**, then explore the tabs and download the CBOM.

Try it first with `demo_repo.zip`: it contains an RSA JWT signer, ECDSA/MD5/AES-128 usage, an X.509 certificate, an RSA private key, nginx and sshd config, a KMS client, and a `docker-compose.yml` that produces a dependency graph.

---

## How risk is scored

Each scored asset gets a 0–100 score from a weighted sum (weights are a configurable policy profile):

| Component | Default weight |
|---|---|
| Quantum vulnerability of the algorithm | 30 |
| Data sensitivity | 20 |
| Business criticality | 15 |
| Exposure | 10 |
| Data lifetime | 10 |
| Migration effort | 10 |
| Dependency impact | 5 |

Severity: **≥ 75 Critical**, **≥ 55 High**, **≥ 35 Medium**, otherwise **Low**.

**Mosca's inequality:** an asset is exposed when `data lifetime (x) + migration time (y) > quantum threat horizon (z)`. For signatures, `x` is how long the signed artefact must remain trustworthy. An exposed quantum-vulnerable asset is raised to at least High.

**Rules worth knowing**
- RSA, ECDSA, ECDH, DH, DSA, EdDSA, and classical TLS/SSH key exchange are treated as fully quantum-vulnerable.
- AES-128, SHA-256 and similar are informational, not high risk. AES-256 is effectively quantum-resistant.
- MD5, SHA-1 and 3DES are flagged as *classical* weaknesses, not quantum risks, and are capped at Medium.
- Findings under `tests/`, `docs/`, `examples/`, `demos/` and similar paths are scored with low-exposure context and capped at Medium; the readiness score counts production code only.

**Recommendations** are based on the cryptographic role, not just the algorithm: signatures map to ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205) for long-lived artefacts; key exchange and encryption map to ML-KEM-768 (FIPS 203). Hybrid migration is suggested for internet-facing or high-criticality assets.

---

## API

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/scan` | Multipart form: `file` (ZIP), `context` (JSON), `horizon`, `weights` (JSON). Returns summary, findings, plan, topology and CBOM |
| `GET` | `/api/cbom/{id}` | Download the CycloneDX CBOM for a scan |

Scan results are held in memory and are lost when the server restarts.

---

## Security notes

- ZIP handling guards against path traversal, oversized files (> 2 MB each, skipped), excessive total size and common dependency folders (`node_modules`, `.git`, `venv`).
- Private-key files are flagged and classified only; their contents are never stored or returned.
- Scan only code and hosts you are authorized to analyze.

---

## Limitations (please read)

- Detection is **pattern-based with light constant tracking**, not full AST or data-flow analysis. Java and Go are regex-only. Expect some false positives (for example, algorithm names in docstrings) and misses.
- Data sensitivity, criticality and lifetime are **user-supplied**; they cannot be inferred from code.
- Risk weights are a starting policy, not a validated standard.
- Library-to-algorithm links in the CBOM are **co-location heuristics** (same service folder), not proof of usage.
- Migration ordering is a transparent heuristic (severity phase, then number of dependent services, then score), not an optimization.
- The what-if slider is an estimate; effort and cost are not modelled.
- Container-image scanning, binary scanning, live TLS endpoint probing, CI/CD mode and LLM explanations are **not implemented** (roadmap).
- The generated CBOM should be validated against the official CycloneDX 1.6 schema before being relied on.
- Verify PQC algorithm and standard status (including FN-DSA / FIPS 206 and HQC) against current NIST publications.

---

## Roadmap

- Container image scanning (`docker save` tarball) and binary library detection
- Live TLS endpoint scanning for hosts you own
- CBOM diff between scans and a GitHub Action / CI mode
- Persistent storage and scan history
- Editable effort/cost assumptions for the what-if simulator
- Optional LLM explanations kept outside the scoring path

---

## References

- NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA)
- NIST NCCoE Migration to Post-Quantum Cryptography project
- CycloneDX Cryptography Bill of Materials (CBOM)
- Mosca's inequality for quantum-risk timing

Research papers cited in project discussions should be opened and verified before being cited in any submission.