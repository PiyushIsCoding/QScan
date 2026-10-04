import { useState } from "react";
import { Overview, Inventory, Risk, Planner } from "./views.jsx";
import "./styles.css";
const TABS = [
  "Overview",
  "Crypto Inventory",
  "Risk & Mosca",
  "Migration Planner",
];
const LV = ["low", "medium", "high", "critical"];
const html = (value) =>
  String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
function printReport(result) {
  const rows = result.findings
    .filter((finding) => finding.risk)
    .slice(0, 40)
    .map(
      (finding) =>
        `<tr><td>${html(finding.risk.severity)}</td><td>${html(finding.algorithm)}</td><td>${html(finding.file)}:${html(finding.line)}</td><td>${html(finding.service)}</td><td>${html(finding.recommendation?.target || "-")}</td></tr>`,
    )
    .join("");
  const report = window.open("", "qscan-report");
  if (!report) return;
  report.document.write(`<!doctype html><html><head><title>QScan report</title><style>
    body{font:14px Arial,sans-serif;color:#17212e;margin:32px}h1{margin-bottom:4px}h2{margin-top:28px}p{color:#526273}.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}.metric{border:1px solid #ccd5df;padding:12px}.metric b{display:block;font-size:26px;margin-top:5px}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:8px;border-bottom:1px solid #dde3e9}th{color:#526273}@media print{body{margin:12mm}.metric{break-inside:avoid}}
  </style></head><body><h1>QScan cryptographic risk report</h1><p>Generated from scan ${html(result.id)}. Print this page or choose Save as PDF.</p><div class="grid"><div class="metric">Readiness<b>${html(result.summary.readiness)}/100</b></div><div class="metric">Findings<b>${html(result.summary.total)}</b></div><div class="metric">Quantum vulnerable<b>${html(result.summary.quantum_vulnerable)}</b></div><div class="metric">Critical / High<b>${html(result.summary.by_severity.CRITICAL || 0)} / ${html(result.summary.by_severity.HIGH || 0)}</b></div></div><h2>Priority findings</h2><table><thead><tr><th>Severity</th><th>Algorithm</th><th>Location</th><th>Service</th><th>Recommendation</th></tr></thead><tbody>${rows}</tbody></table><script>window.onload=()=>window.print();</script></body></html>`);
  report.document.close();
}
export default function App() {
  const [R, setR] = useState(null),
    [tab, setTab] = useState(0),
    [busy, setBusy] = useState(false),
    [err, setErr] = useState(""),
    [file, setFile] = useState(null);
  const [p, setP] = useState({
    sens: "high",
    crit: "critical",
    exp: "internet",
    life: 12,
    mig: 3,
    hz: "moderate",
    ov: "",
  });
  const set = (k) => (e) => setP({ ...p, [k]: e.target.value });
  const Sel = ({ k, opts }) => (
    <select value={p[k]} onChange={set(k)}>
      {opts.map((o) => (
        <option key={o}>{o}</option>
      ))}
    </select>
  );
  async function scan() {
    if (!file) return setErr("Choose a ZIP first");
    let ov = {};
    try {
      ov = JSON.parse(p.ov || "{}");
    } catch {
      return setErr("Override JSON is invalid");
    }
    const ctx = {
      default: {
        sensitivity: p.sens,
        criticality: p.crit,
        exposure: p.exp,
        data_lifetime_years: +p.life,
        migration_years: +p.mig,
      },
      ...ov,
    };
    const fd = new FormData();
    fd.append("file", file);
    fd.append("context", JSON.stringify(ctx));
    fd.append("horizon", p.hz);
    setBusy(true);
    setErr("");
    try {
      const r = await fetch("/api/scan", { method: "POST", body: fd });
      const j = await r.json();
      if (!r.ok) throw new Error(j.detail || "Scan failed");
      setR(j);
      setTab(0);
    } catch (e) {
      setErr(e.message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <>
      <header>
        <h1>
          Q<span>SCAN</span>
        </h1>
        <span className="mu">
          cryptographic discovery · CBOM · quantum risk · PQC migration
        </span>
      </header>
      <main>
        <div className="card">
          <div className="row">
            <label>
              Repository ZIP
              <input
                type="file"
                accept=".zip"
                onChange={(e) => setFile(e.target.files[0])}
              />
            </label>
            <label>
              Sensitivity
              <Sel k="sens" opts={LV} />
            </label>
            <label>
              Criticality
              <Sel k="crit" opts={LV} />
            </label>
            <label>
              Exposure
              <select value={p.exp} onChange={set("exp")}>
                <option value="internal">internal</option>
                <option value="internet">internet-facing</option>
              </select>
            </label>
            <label>
              Data lifetime (yrs)
              <input
                type="number"
                value={p.life}
                onChange={set("life")}
                style={{ width: 90 }}
              />
            </label>
            <label>
              Migration time (yrs)
              <input
                type="number"
                value={p.mig}
                onChange={set("mig")}
                style={{ width: 90 }}
              />
            </label>
            <label>
              Threat horizon
              <select value={p.hz} onChange={set("hz")}>
                <option value="conservative">conservative 10y</option>
                <option value="moderate">moderate 15y</option>
                <option value="aggressive">aggressive 20y</option>
              </select>
            </label>
            <button onClick={scan} disabled={busy}>
              {busy ? "Scanning…" : "Scan"}
            </button>
          </div>
          <p className="mu" style={{ margin: "10px 0 0" }}>
            Context is user-supplied. Overrides &amp; dependencies (JSON):{" "}
            <input
              style={{ width: 520 }}
              placeholder='{"payment-service":{"sensitivity":"critical"},"deps":{"payment-service":["auth-service"]}}'
              value={p.ov}
              onChange={set("ov")}
            />
          </p>
          {err && <p style={{ color: "#ff5d73", margin: "8px 0 0" }}>{err}</p>}
        </div>
        {R && (
          <>
            <div className="row" style={{ justifyContent: "flex-end", marginBottom: 10 }}>
              <button className="ghost" onClick={() => printReport(R)}>
                Print report / Save PDF
              </button>
            </div>
            <nav>
              {TABS.map((t, i) => (
                <a
                  key={t}
                  className={i === tab ? "on" : ""}
                  onClick={() => setTab(i)}
                >
                  {t}
                </a>
              ))}
            </nav>
            {tab === 0 && <Overview R={R} />}
            {tab === 1 && <Inventory R={R} />}
            {tab === 2 && <Risk R={R} />}
            {tab === 3 && <Planner R={R} />}
          </>
        )}
      </main>
    </>
  );
}
