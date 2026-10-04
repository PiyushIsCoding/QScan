# QScan 3-Minute Demo

## Before the demo

1. Start the backend:

   ```bash
   uvicorn app:app --reload
   ```

2. Start the frontend in a second terminal:

   ```bash
   cd frontend
   npm run dev
   ```

3. Open `http://localhost:5173` and select `demo_repo (1).zip`.

## Presentation flow

### 0:00-0:30 - Discover

Set sensitivity to high, criticality to critical, internet exposure, and a moderate 15-year horizon. Click **Scan**. Explain that QScan inspects source files, manifests, certificates, protocol configuration, KMS/HSM references, and dependency topology.

### 0:30-1:10 - Overview

Show readiness, scored assets, quantum-vulnerable assets, and Critical/High counts. Point out the severity distribution and the service-level view. Explain that the context is user-supplied because the scanner cannot infer business sensitivity from source code.

### 1:10-1:40 - Inventory

Open **Crypto Inventory**. Search for `RSA` or `MD5`, select a finding, and show its location, evidence, confidence, risk, Mosca context, and recommendation. Emphasize that private-key contents are classified but never returned.

### 1:40-2:15 - Risk and migration

Open **Risk & Mosca** and explain `x + y > z`: data lifetime plus migration time exceeds the threat horizon. Open **Migration Planner** to show dependency-aware ordering and the what-if readiness slider.

### 2:15-2:40 - CBOM and report

Download the CycloneDX 1.6 CBOM. Return to the dashboard and click **Print report / Save PDF** to demonstrate the browser-printable report.

### 2:40-3:00 - Honest close

State that the prototype uses pattern detection with light constant tracking, not full AST/data-flow analysis. Findings are source-backed but may represent references or capability lists rather than confirmed runtime use. Risk weights and context are configurable policy inputs. Container scanning, binary scanning, persistence, CI mode, and live TLS probing are roadmap items.

## Fallback

If Vite is unavailable, build once and serve the production UI through FastAPI:

```bash
cd frontend
npm run build
cd ..
uvicorn app:app
```

Open `http://localhost:8000`. If `frontend/dist` is absent, FastAPI serves the legacy dashboard.

## Evidence prepared

- Demo CBOM passes the official CycloneDX 1.6 JSON schema.
- Paramiko CBOM passes the official CycloneDX 1.6 JSON schema.
- Three scanner regression tests pass.
- Demo scan contains 15 findings and Paramiko scan contains 110 findings.
- No private-key contents appear in serialized scan output.
