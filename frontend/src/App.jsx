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
