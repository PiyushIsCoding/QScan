import { useMemo, useState } from "react";
export const SEV = {
  CRITICAL: "#ff5d73",
  HIGH: "#ff9f45",
  MEDIUM: "#f5d547",
  LOW: "#5fd38d",
};
const RANK = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
const Tag = ({ s }) =>
  s ? (
    <span className="tag" style={{ background: SEV[s] }}>
      {s}
    </span>
  ) : (
    <span className="mu">—</span>
  );
const K = ({ l, v, sub, c }) => (
  <div className="card k">
    <span className="mu">{l}</span>
    <b style={{ color: c }}>{v}</b>
    <span className="mu">{sub}</span>
  </div>
);
const worst = (R, s) =>
  R.findings
    .filter((f) => f.service === s && f.risk)
    .reduce(
      (m, f) => (RANK[f.risk.severity] > (RANK[m] || 0) ? f.risk.severity : m),
      null,
    );

export function Overview({ R }) {
  const s = R.summary,
    b = s.by_severity,
    tot = Object.values(b).reduce((a, c) => a + c, 0) || 1;
  const svcs = [...new Set(R.findings.map((f) => f.service))];
  const types = Object.entries(
    R.findings.reduce(
      (m, f) => ((m[f.asset_type] = (m[f.asset_type] || 0) + 1), m),
      {},
    ),
  );
  return (
    <>
      <div className="kpis">
        <K
          l="Quantum readiness"
          v={s.readiness}
          sub="/100 · production code"
          c={s.readiness < 50 ? SEV.CRITICAL : SEV.LOW}
        />
        <K
          l="Scored assets"
          v={s.scored}
          sub={`${s.total - s.scored} libraries / keystores`}
        />
        <K
          l="Quantum-vulnerable"
          v={s.quantum_vulnerable}
          sub={`${s.prod_quantum_vulnerable} in production code`}
        />
        <K
          l="Critical / High"
          v={`${b.CRITICAL || 0} / ${b.HIGH || 0}`}
          sub={`threat horizon ${s.horizon_years}y`}
        />
      </div>
      <div className="two">
        <div className="card">
          <h3>Severity distribution</h3>
          {Object.keys(SEV).map((k) => (
            <div key={k} style={{ margin: "8px 0" }}>
              {k} {b[k] || 0}
              <div className="bar">
                <i
                  style={{
                    width: `${((b[k] || 0) / tot) * 100}%`,
                    background: SEV[k],
                  }}
                />
              </div>
            </div>
          ))}
          <a className="btn ghost" href={`/api/cbom/${R.id}`}>
            Download CycloneDX CBOM (JSON)
          </a>
        </div>
        <div className="card">
          <h3>Asset types</h3>
          {types.map(([t, n]) => (
            <div
              key={t}
              className="row"
              style={{ justifyContent: "space-between" }}
            >
              <span>{t}</span>
              <b>{n}</b>
            </div>
          ))}
        </div>
      </div>
      <div className="card">
        <h3>By service</h3>
        <table>
          <thead>
            <tr>
              <th>Service</th>
              <th>Assets</th>
              <th>Worst severity</th>
            </tr>
          </thead>
          <tbody>
            {svcs.map((s) => (
              <tr key={s}>
                <td>{s}</td>
                <td>{R.findings.filter((f) => f.service === s).length}</td>
                <td>
                  <Tag s={worst(R, s)} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}

export function Inventory({ R }) {
  const [q, setQ] = useState(""),
    [sev, setSev] = useState(""),
    [type, setType] = useState(""),
    [scope, setScope] = useState(""),
    [sel, setSel] = useState(null);
  const rows = useMemo(
    () =>
      R.findings.filter(
        (f) =>
          (!sev || f.risk?.severity === sev) &&
          (!type || f.asset_type === type) &&
          (!scope || f.scope === scope) &&
          (!q ||
            (f.algorithm + f.file + f.service)
              .toLowerCase()
              .includes(q.toLowerCase())),
      ),
    [R, q, sev, type, scope],
  );
  const types = [...new Set(R.findings.map((f) => f.asset_type))];
  return (
    <div className="split">
      <div className="card" style={{ flex: 1, minWidth: 0 }}>
        <div className="row" style={{ marginBottom: 10 }}>
          <input
            placeholder="Search algorithm / file / service"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            style={{ width: 260 }}
          />
          <select value={sev} onChange={(e) => setSev(e.target.value)}>
            <option value="">all severities</option>
            {Object.keys(SEV).map((k) => (
              <option key={k}>{k}</option>
            ))}
          </select>
          <select value={type} onChange={(e) => setType(e.target.value)}>
            <option value="">all types</option>
            {types.map((k) => (
              <option key={k}>{k}</option>
            ))}
          </select>
          <select value={scope} onChange={(e) => setScope(e.target.value)}>
            <option value="">prod + test</option>
            <option value="prod">prod</option>
            <option value="test">test</option>
          </select>
          <span className="mu">
            {rows.length} of {R.findings.length}
          </span>
        </div>
        <div style={{ overflowX: "auto" }}>
          <table>
            <thead>
              <tr>
                <th>ID</th>
                <th>Type</th>
                <th>Algorithm</th>
                <th>Location</th>
                <th>Service</th>
                <th>Conf.</th>
                <th>Risk</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((f) => (
                <tr
                  key={f.id}
                  className={`cl ${sel?.id === f.id ? "sel" : ""}`}
                  onClick={() => setSel(f)}
                >
                  <td>{f.id}</td>
                  <td>{f.asset_type}</td>
                  <td>
                    <code>{f.algorithm}</code>
                  </td>
                  <td>
                    {f.file}:{f.line}
                  </td>
                  <td>
                    {f.service}
                    {f.scope === "test" && <span className="mu"> [test]</span>}
                  </td>
                  <td>{Math.round(f.confidence * 100)}%</td>
                  <td>
                    <Tag s={f.risk?.severity} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
      {sel && (
        <aside className="card drawer">
          <div className="row" style={{ justifyContent: "space-between" }}>
            <h3>
              <code>{sel.algorithm}</code>
            </h3>
            <a onClick={() => setSel(null)} className="mu">
              close
            </a>
          </div>
          <p className="mu">
            {sel.file}:{sel.lines?.join(", ") || sel.line} · {sel.purpose}
          </p>
          <h4>Evidence</h4>
          <ul>
            {sel.evidence.map((e, i) => (
              <li key={i}>
                <code>{e}</code>
              </li>
            ))}
          </ul>
          {sel.not_after && (
            <p>
              Validity {sel.not_before.slice(0, 10)} →{" "}
              {sel.not_after.slice(0, 10)} ({sel.lifetime_years}y)
            </p>
          )}
          {sel.risk && (
            <>
              <h4>
                Risk <Tag s={sel.risk.severity} /> {sel.risk.score}
              </h4>
              <p className="mu">{sel.risk.quantum_note}</p>
            </>
          )}
          {sel.recommendation && (
            <>
              <h4>Recommendation</h4>
              <p>
                <b>{sel.recommendation.target}</b> (
                {sel.recommendation.standard})
              </p>
              <p>{sel.recommendation.strategy}</p>
              <p className="mu">{sel.recommendation.size_note}</p>
              <p className="mu">{sel.recommendation.rationale}</p>
            </>
          )}
        </aside>
      )}
    </div>
  );
}

export function Risk({ R }) {
  const [all, setAll] = useState(false);
  const rs = R.findings
      .filter((f) => f.risk)
      .sort((a, b) => b.risk.score - a.risk.score),
    shown = all ? rs : rs.slice(0, 30);
  return (
    <>
      <div className="card mu">
        Mosca: exposed when{" "}
        <b>
          data lifetime (x) + migration time (y) &gt; quantum threat horizon (z
          = {R.summary.horizon_years}y)
        </b>
        . For signatures, x = how long the signed artefact must stay
        trustworthy.
      </div>
      {shown.map((f) => {
        const r = f.risk,
          m = r.mosca;
        return (
          <div className="card" key={f.id}>
            <div className="row" style={{ justifyContent: "space-between" }}>
              <b>
                <code>{f.algorithm}</code> — {f.file}:{f.line}
              </b>
              <Tag s={r.severity} />
            </div>
            <div className="mu">
              {r.quantum_note} · score {r.score}/100 · {r.context.exposure},{" "}
              {r.context.sensitivity} sensitivity, {r.context.criticality}{" "}
              criticality
            </div>
            <div style={{ margin: "8px 0" }}>
              Mosca: {m.x} + {m.y} = {m.x + m.y}y vs {m.z}y →{" "}
              <b style={{ color: m.exposed ? SEV.CRITICAL : SEV.LOW }}>
                {m.exposed
                  ? `EXPOSED by ${-m.margin_years}y`
                  : `safe, margin ${m.margin_years}y`}
              </b>
            </div>
            {Object.entries(r.components).map(([k, v]) => (
              <div key={k} className="row" style={{ gap: 8 }}>
                <span className="mu" style={{ width: 110 }}>
                  {k}
                </span>
                <div className="bar" style={{ flex: 1 }}>
                  <i style={{ width: `${v}%`, background: "#4fd1c5" }} />
                </div>
              </div>
            ))}
          </div>
        );
      })}
      {!all && rs.length > 30 && (
        <button className="ghost" onClick={() => setAll(true)}>
          Show all {rs.length}
        </button>
      )}
    </>
  );
}

function Graph({ R }) {
  const topo = R.topology || {},
    edges = Object.entries(topo).flatMap(([s, ds]) => ds.map((d) => [s, d]));
  if (!edges.length)
    return (
      <div className="card mu">
        No service dependencies found. Add a docker-compose.yml with depends_on,
        or pass {'{"deps":{"a":["b"]}}'} in the context JSON.
      </div>
    );
  const svcs = [
    ...new Set([
      ...R.findings.map((f) => f.service),
      ...Object.keys(topo),
      ...edges.map((e) => e[1]),
    ]),
  ];
  const lvl = {};
  const L = (s, d = 0) =>
    d > 8
      ? 0
      : lvl[s] !== undefined
        ? lvl[s]
        : (lvl[s] = (topo[s] || []).length
            ? 1 + Math.max(...topo[s].map((x) => L(x, d + 1)))
            : 0);
  svcs.forEach((s) => L(s));
  const cols = {};
  svcs.forEach((s) => {
    (cols[lvl[s]] = cols[lvl[s]] || []).push(s);
  });
  const pos = {};
  Object.entries(cols).forEach(([l, ss]) =>
    ss.forEach((s, i) => (pos[s] = { x: 30 + l * 230, y: 30 + i * 70 })),
  );
  const W = (Math.max(...Object.keys(cols).map(Number)) + 1) * 230 + 20,
    H = Math.max(...Object.values(cols).map((c) => c.length)) * 70 + 20;
  return (
    <div className="card" style={{ overflowX: "auto" }}>
      <h3>
        Service dependency graph{" "}
        <span className="mu">
          (arrow: depends on · providers migrate first)
        </span>
      </h3>
      <svg width={W} height={H}>
        <defs>
          <marker
            id="ar"
            markerWidth="8"
            markerHeight="8"
            refX="7"
            refY="4"
            orient="auto"
          >
            <path d="M0,0 L8,4 L0,8 z" fill="#7f93a8" />
          </marker>
        </defs>
        {edges.map(
          ([s, d], i) =>
            pos[s] &&
            pos[d] && (
              <line
                key={i}
                x1={pos[s].x}
                y1={pos[s].y + 20}
                x2={pos[d].x + 170}
                y2={pos[d].y + 20}
                stroke="#7f93a8"
                markerEnd="url(#ar)"
              />
            ),
        )}
        {svcs.map((s) => (
          <g key={s}>
            <rect
              x={pos[s].x}
              y={pos[s].y}
              width="170"
              height="40"
              rx="6"
              fill="#121923"
              stroke={SEV[worst(R, s)] || "#243041"}
              strokeWidth="2"
            />
            <text
              x={pos[s].x + 10}
              y={pos[s].y + 17}
              fill="#d6e2f0"
              fontSize="13"
            >
              {s.slice(0, 22)}
            </text>
            <text
              x={pos[s].x + 10}
              y={pos[s].y + 32}
              fill="#7f93a8"
              fontSize="11"
            >
              {R.findings.filter((f) => f.service === s && f.risk).length}{" "}
              scored assets
            </text>
          </g>
        ))}
      </svg>
    </div>
  );
}

export function Planner({ R }) {
  const [n, setN] = useState(0),
    [st, setSt] = useState({});
  const prod = R.findings.filter((f) => f.risk && f.scope === "prod"),
    done = new Set(R.plan.slice(0, n).map((p) => p.id));
  const rem = prod.filter((f) => !done.has(f.id)),
    proj = rem.length
      ? Math.round(100 - rem.reduce((a, f) => a + f.risk.score, 0) / rem.length)
      : 100;
  return (
    <>
      <Graph R={R} />
      <div className="card">
        <h3>What-if: migrate the top N plan items</h3>
        <div className="row">
          <input
            type="range"
            min="0"
            max={R.plan.length}
            value={n}
            onChange={(e) => setN(+e.target.value)}
            style={{ flex: 1 }}
          />
          <span>
            N = <b>{n}</b>
          </span>
          <span>
            Projected readiness:{" "}
            <b style={{ color: proj < 50 ? SEV.CRITICAL : SEV.LOW }}>{proj}</b>{" "}
            <span className="mu">(now {R.summary.readiness})</span>
          </span>
        </div>
        <p className="mu" style={{ margin: "6px 0 0" }}>
          Estimate: removes migrated assets from the production risk average.
          Effort/cost need an assumptions table (not modelled).
        </p>
      </div>
      <div className="card" style={{ overflowX: "auto" }}>
        <table>
          <thead>
            <tr>
              <th>#</th>
              <th>Phase</th>
              <th>Asset</th>
              <th>Service</th>
              <th>Severity</th>
              <th>Score</th>
              <th>Unblocks</th>
              <th>Migrate to</th>
              <th>Strategy</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {R.plan.map((p) => (
              <tr key={p.id} style={{ opacity: p.order <= n ? 0.45 : 1 }}>
                <td>{p.order}</td>
                <td>P{p.phase}</td>
                <td>
                  <code>{p.asset}</code>
                  <br />
                  <span className="mu">{p.file}</span>
                </td>
                <td>{p.service}</td>
                <td>
                  <Tag s={p.severity} />
                </td>
                <td>{p.score}</td>
                <td>{p.blocks || 0}</td>
                <td>{p.target || "—"}</td>
                <td>{p.strategy}</td>
                <td>
                  <select
                    value={st[p.id] || "todo"}
                    onChange={(e) => setSt({ ...st, [p.id]: e.target.value })}
                  >
                    <option>todo</option>
                    <option>in-progress</option>
                    <option>done</option>
                  </select>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}
