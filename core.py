"""QScan core: discover -> normalize -> CBOM -> quantum risk (Mosca) -> PQC recs -> migration plan."""
import io, re, json, zipfile, uuid, datetime

try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
except Exception:  # certs degrade to header detection
    x509 = None

TEST_RX = re.compile(r"(^|/)(tests?|testing|docs?|examples?|demos?|samples?|fixtures|benchmarks?|e2e)(/|$)|(^|/)(test_[^/]*|[^/]*_test\.\w+|[^/]*\.(test|spec)\.\w+)$", re.I)
MANIFESTS = ("requirements.txt", "package.json", "pom.xml", "go.mod", "Cargo.toml", "pyproject.toml", "setup.py", "setup.cfg", "Pipfile")
CONF_EXT = {".conf", ".cfg", ".tf", ".yml", ".yaml", ".ini", ".toml", ".env"}
SCORED = ("algorithm", "certificate", "private-key", "protocol", "cloud-service", "hardware-module")
CONFIG_RULES = [  # regex, asset_type, family, name(match), purpose
    (r"(?i)^\s*ssl_protocols\s+([^;]+);", "protocol", "TLS", lambda m: "TLS (" + m.group(1).strip() + ")", "TLS handshake (classical key exchange)"),
    (r"(?i)^\s*ssl_ciphers\s+['\"]?([^;'\"]+)", "protocol", "TLS", lambda m: "TLS ciphers (" + m.group(1).strip()[:40] + ")", "TLS cipher suites"),
    (r"(?i)^\s*(KexAlgorithms|HostKeyAlgorithms|PubkeyAcceptedAlgorithms)\s+(\S+)", "protocol", "SSH", lambda m: "SSH " + m.group(1) + " (" + m.group(2)[:40] + ")", "SSH key exchange / host keys"),
    (r"(?i)boto3\.client\(\s*['\"]kms|aws_kms_key|azurerm_key_vault_key|google_kms_crypto_key|KeyManagementServiceClient", "cloud-service", "CLOUDKMS", lambda m: "Cloud KMS", "managed key service"),
    (r"(?i)pkcs11|softhsm|cloudhsm|\bhsm_", "hardware-module", "HSM", lambda m: "HSM / PKCS#11", "hardware security module"),
]
SKIP_DIRS = ("node_modules/", ".git/", "venv/", "__pycache__/", "dist/")
CODE_EXT = {".py": "python", ".js": "javascript", ".ts": "javascript", ".jsx": "javascript",
            ".java": "java", ".go": "go"}

# regex, family, default purpose
RULES = [
    (r"(?i)\brsa\b|generateKeyPairSync\(\s*['\"]rsa|RSA-SHA\d+", "RSA", "signature"),
    (r"(?i)\becdsa\b|ec\.generate_private_key|secp\d+r1|prime256v1|secp256k1|P-256|P-384", "ECDSA", "signature"),
    (r"(?i)\becdh\b|createECDH|x25519", "ECDH", "key-exchange"),
    (r"(?i)diffie|createDiffieHellman|\bDH\b", "DH", "key-exchange"),
    (r"(?i)ed25519|ed448", "EdDSA", "signature"),
    (r"\bDSA\b", "DSA", "signature"),
    (r"(?i)\baes[-_]?(128|192|256)?\b|createCipheriv", "AES", "encryption"),
    (r"(?i)\b3des\b|des-ede3|triple.?des", "3DES", "encryption"),
    (r"(?i)\bmd5\b", "MD5", "hash"),
    (r"(?i)\bsha-?1\b", "SHA-1", "hash"),
    (r"(?i)\bsha-?256\b", "SHA-256", "hash"),
]
LIBS = {  # manifest dependency -> crypto capability
    "cryptography": "general crypto (RSA/EC/AES)", "pycryptodome": "general crypto", "pycrypto": "legacy crypto",
    "pyopenssl": "OpenSSL/TLS", "paramiko": "SSH (RSA/ECDSA/DH)", "pyjwt": "JWT signing (RSA/ECDSA)",
    "jsonwebtoken": "JWT signing (RSA/ECDSA)", "node-forge": "general crypto/TLS", "bcrypt": "password hashing",
    "jose": "JOSE/JWT", "bouncycastle": "general crypto", "bcprov": "general crypto", "crypto-js": "AES/hash",
    "liboqs": "PQC library", "oqs": "PQC library", "pqcrypto": "PQC library",
}
# family -> (quantum vulnerability 0-100, note)
ALGO = {
    "RSA": (100, "Broken by Shor's algorithm"), "ECDSA": (100, "Broken by Shor's algorithm"),
    "ECDH": (100, "Broken by Shor's algorithm"), "DH": (100, "Broken by Shor's algorithm"),
    "DSA": (100, "Broken by Shor's algorithm"), "EdDSA": (100, "Broken by Shor's algorithm"),
    "AES-128": (20, "Grover halves margin; still acceptable"), "AES-192": (10, "Acceptable"),
    "AES-256": (5, "Quantum-resistant"), "AES": (15, "Key size unknown; verify >=256 preferred"),
    "SHA-256": (10, "Informational"), "3DES": (40, "Classically weak; retire"),
    "TLS": (90, "Classical handshake key exchange: harvest-now-decrypt-later risk"), "SSH": (90, "Classical key exchange / host keys"),
    "KEY": (90, "Key type unknown; assume asymmetric"), "CLOUDKMS": (50, "Key specs must be checked; RSA/EC keys are quantum-vulnerable"),
    "HSM": (50, "Verify vendor PQC firmware roadmap"),
    "MD5": (30, "Classically broken (not a quantum issue)"), "SHA-1": (30, "Classically broken (not a quantum issue)"),
}
LEVEL = {"low": 25, "medium": 50, "high": 75, "critical": 100}
DEFAULT_CTX = {"sensitivity": "high", "criticality": "high", "exposure": "internal",
               "data_lifetime_years": 10, "migration_years": 3, "migration_effort": "medium"}
DEFAULT_WEIGHTS = {"quantum": 30, "sensitivity": 20, "criticality": 15, "exposure": 10,
                   "lifetime": 10, "effort": 10, "dependency": 5}
HORIZONS = {"conservative": 10, "moderate": 15, "aggressive": 20}
SIZES = {  # bytes, from FIPS 203/204/205 + classical
    "ML-KEM-768": "pk 1184 B, ct 1088 B (vs X25519 32 B)",
    "ML-DSA-65": "pk 1952 B, sig 3309 B (vs ECDSA P-256 sig 64 B, RSA-2048 sig 256 B)",
    "SLH-DSA-128s": "pk 32 B, sig 7856 B (slow signing, hash-based, conservative)",
}


def _purpose(line, default):
    l = line.lower()
    if re.search(r"sign|verify|signature|jwt|cert", l): return "signature"
    if re.search(r"encrypt|decrypt|cipher", l): return "encryption"
    if re.search(r"exchange|derive|ecdh|handshake|kem|dh\b", l): return "key-exchange"
    if re.search(r"hash|digest", l): return "hash"
    return default


def _key_size(family, line, consts):
    if family == "AES":
        m = re.search(r"(?i)aes[-_]?(128|192|256)", line)
        return m.group(1) if m else None
    if family in ("RSA", "DSA", "DH"):
        for m in re.finditer(r"\b(1024|2048|3072|4096|7680|8192)\b", line):
            return m.group(1)
        for name in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", line):  # lightweight constant tracking
            if consts.get(name) in (1024, 2048, 3072, 4096, 8192): return str(consts[name])
    if family == "ECDSA":
        m = re.search(r"(?:secp|P-?)(256|384|521)", line)
        return m.group(1) if m else None
    return None


def _norm(family, size):
    if family == "AES" and size: return f"AES-{size}"
    if family == "ECDSA" and size: return f"ECDSA-P{size}"
    return f"{family}-{size}" if size else family


def _scan_code(path, text, lang):
    out, consts = [], {}
    for m in re.finditer(r"^\s*(?:const |let |var )?([A-Za-z_]\w*)\s*[:=]\s*(\d{3,5})\s*;?\s*$", text, re.M):
        consts[m.group(1)] = int(m.group(2))
    for i, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if not s or s.startswith(("#", "//", "*", "/*")): continue
        for rx, fam, dflt in RULES:
            if re.search(rx, line):
                size = _key_size(fam, line, consts)
                resolved = size is not None and not re.search(r"\b%s\b" % size, line)
                conf = 0.55 + (0.2 if size else 0) + (0.1 if re.search(r"\(|\.", s) else 0)
                out.append(dict(asset_type="algorithm", family=fam, algorithm=_norm(fam, size), key_size=size,
                                purpose=_purpose(line, dflt), file=path, line=i, language=lang,
                                evidence=[s[:140]] + (["key size resolved from constant"] if resolved else []),
                                confidence=round(min(conf, 0.95), 2)))
    return out


def _scan_config(path, text):
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        if line.strip().startswith("#"): continue
        for rx, atype, fam, name, purpose in CONFIG_RULES:
            m = re.search(rx, line)
            if m: out.append(dict(asset_type=atype, family=fam, algorithm=name(m), key_size=None, purpose=purpose, file=path, line=i,
                                  language="config", evidence=[line.strip()[:140]], confidence=0.85))
    return out


def _compose(text, topo):
    svc, in_dep, insvc, alias = None, False, False, {}
    for line in text.splitlines():
        if re.match(r"^\S", line): insvc = line.startswith("services:"); svc = None; continue
        m = re.match(r"^  ([\w.-]+):\s*$", line)
        if m and insvc: svc, in_dep = m.group(1), False; topo.setdefault(svc, []); continue
        if not svc: continue
        m = re.match(r"^    depends_on:\s*\[(.*)\]", line)
        if m: topo[svc] += [x.strip(" '\"") for x in m.group(1).split(",") if x.strip()]; in_dep = False; continue
        if re.match(r"^    depends_on:\s*$", line): in_dep = True; continue
        m = re.match(r"^    build:\s*(?:\./)?([\w.-]+)", line)
        if m and m.group(1) != ".": alias[svc] = m.group(1)
        if in_dep:
            m = re.match(r"^      -\s*([\w.-]+)", line) or re.match(r"^      ([\w.-]+):\s*$", line)
            if m: topo[svc].append(m.group(1))
            elif re.match(r"^    \S", line): in_dep = False
    ren, new = (lambda x: alias.get(x, x)), {}
    for k, ds in topo.items(): new.setdefault(ren(k), []); new[ren(k)] += [ren(d) for d in ds]
    topo.clear(); topo.update(new)


def _scan_manifest(path, text):
    name = path.rsplit("/", 1)[-1]
    if name not in MANIFESTS: return []
    out, low = [], text.lower()
    for lib, cap in LIBS.items():
        m = re.search(r"(?<![\w-])%s(?![\w-])" % re.escape(lib), low)
        if m:
            line = low[:m.start()].count("\n") + 1
            out.append(dict(asset_type="library", family="LIB", algorithm=lib, key_size=None, purpose=cap, file=path,
                            line=line, language="manifest", evidence=[f"dependency '{lib}' in {name}"], confidence=0.9))
    return out


def _scan_cert(path, data):
    out = []
    if path.endswith((".p12", ".pfx", ".jks")):
        return [dict(asset_type="keystore", family="KEYSTORE", algorithm="keystore", key_size=None,
                     purpose="key storage (password protected, not parsed)", file=path, line=0, language="binary",
                     evidence=["keystore file present"], confidence=0.95)]
    txt = data.decode("utf8", "ignore")
    mk = re.search(r"-----BEGIN (RSA |EC |ENCRYPTED |OPENSSH |DSA )?PRIVATE KEY-----", txt)
    if mk:  # flag + classify only; never store contents
        fam, size = {"RSA": ("RSA", None), "EC": ("ECDSA", None), "DSA": ("DSA", None)}.get((mk.group(1) or "").strip(), ("KEY", None))
        if x509:
            try:
                k = load_pem_private_key(txt.encode(), None)
                fam, size = (("RSA", k.key_size) if isinstance(k, rsa.RSAPrivateKey) else ("ECDSA", k.curve.key_size) if isinstance(k, ec.EllipticCurvePrivateKey)
                             else ("DSA", k.key_size) if isinstance(k, dsa.DSAPrivateKey) else ("EdDSA", None))
            except Exception: pass
        out.append(dict(asset_type="private-key", family=fam, algorithm=_norm(fam, str(size) if size else None) if fam != "KEY" else "private-key",
                        key_size=str(size) if size else None, purpose="private key file (contents not stored)", file=path, line=1, language="pem",
                        evidence=["PEM private key header"], confidence=0.95))
    if "BEGIN CERTIFICATE" in txt and x509:
        try:
            c = x509.load_pem_x509_certificate(txt.encode())
            k = c.public_key()
            fam, size = (("RSA", k.key_size) if isinstance(k, rsa.RSAPublicKey) else
                         ("ECDSA", k.curve.key_size) if isinstance(k, ec.EllipticCurvePublicKey) else
                         ("DSA", k.key_size) if isinstance(k, dsa.DSAPublicKey) else ("EdDSA", None))
            nb, na = c.not_valid_before_utc, c.not_valid_after_utc
            out.append(dict(asset_type="certificate", family=fam, algorithm=_norm(fam, str(size) if size else None),
                            key_size=str(size) if size else None, purpose="signature", file=path, line=1,
                            language="x509", subject=c.subject.rfc4514_string(), issuer=c.issuer.rfc4514_string(),
                            not_before=nb.isoformat(), not_after=na.isoformat(),
                            lifetime_years=round((na - nb).days / 365.25, 1),
                            evidence=[f"X.509 public key {fam}", f"signature hash {c.signature_hash_algorithm.name}"],
                            confidence=0.99))
        except Exception as e:
            out.append(dict(asset_type="certificate", family="CERT", algorithm="certificate", key_size=None,
                            purpose="unparsed", file=path, line=1, language="x509", evidence=[f"parse error: {e}"],
                            confidence=0.5))
    return out


def scan_zip(blob, max_total=80_000_000, topo=None):
    zf, findings, total = zipfile.ZipFile(io.BytesIO(blob)), [], 0
    names = [i.filename for i in zf.infolist() if not i.is_dir()]
    roots = {n.split("/")[0] for n in names if "/" in n}
    root = (roots.pop() + "/") if len(roots) == 1 and all("/" in n for n in names) else ""  # GitHub ZIPs have one root dir
    for info in zf.infolist():
        p = info.filename
        if root and p.startswith(root): p = p[len(root):]
        if not p: continue
        if info.is_dir() or ".." in p or p.startswith("/") or any(d in p for d in SKIP_DIRS): continue
        if info.file_size > 2_000_000: continue  # zip-bomb / size guard
        total += info.file_size
        if total > max_total: break
        data, ext = zf.read(info.filename), "." + p.rsplit(".", 1)[-1].lower() if "." in p else ""
        if ext in CODE_EXT: findings += _scan_code(p, data.decode("utf8", "ignore"), CODE_EXT[ext])
        elif ext in (".pem", ".crt", ".cer", ".key", ".p12", ".pfx", ".jks"): findings += _scan_cert(p, data)
        base = p.rsplit("/", 1)[-1]
        findings += _scan_manifest(p, data.decode("utf8", "ignore")) if base in MANIFESTS else []
        if ext in CODE_EXT or ext in CONF_EXT or base in ("sshd_config", "ssh_config", "Dockerfile"):
            findings += _scan_config(p, data.decode("utf8", "ignore"))
        if base in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml") and topo is not None:
            _compose(data.decode("utf8", "ignore"), topo)
    merged = {}
    for f in findings:
        k = (f["file"], f["family"], f["asset_type"], f["algorithm"] if f["asset_type"] == "library" else "")
        if f["asset_type"] == "algorithm" and f["family"] in ("MD5", "SHA-1", "SHA-256", "3DES", "AES"): f["purpose"] = "hash" if f["family"] in ("MD5", "SHA-1", "SHA-256") else f["purpose"]
        if k not in merged: f["lines"] = [f["line"]]; merged[k] = f; continue
        b = merged[k]; b["lines"].append(f["line"])
        if (f["key_size"] is not None, f["confidence"]) > (b["key_size"] is not None, b["confidence"]):
            f["lines"] = b["lines"]; merged[k] = b = f
        b["evidence"] = list(dict.fromkeys(b["evidence"] + f["evidence"]))[:4]
    findings = list(merged.values())
    for n, f in enumerate(findings, 1):
        f["id"] = f"A{n:03d}"
        f["service"] = f["file"].split("/")[0] if "/" in f["file"] else "app"
        f["scope"] = "test" if TEST_RX.search(f["file"]) else "prod"
    return findings


def recommend(f, ctx):
    fam, purpose = f["family"], f["purpose"]
    hybrid = ctx["exposure"] == "internet" or LEVEL.get(ctx["criticality"], 50) >= 75
    if fam == "TLS": return dict(target="Hybrid X25519MLKEM768 key exchange", standard="FIPS 203 + IETF hybrid TLS draft", strategy="Hybrid migration", size_note=SIZES["ML-KEM-768"], rationale="Classical TLS key exchange is exposed to harvest-now-decrypt-later")
    if fam == "SSH": return dict(target="Hybrid PQ KEX (mlkem768x25519-sha256 / sntrup761x25519-sha512)", standard="OpenSSH hybrid KEX", strategy="Hybrid migration", size_note="", rationale="Enable a hybrid KexAlgorithms entry on recent OpenSSH; verify client/server version support")
    if fam in ("CLOUDKMS", "HSM"): return dict(target="PQC-capable KMS/HSM keys (vendor roadmap)", standard="FIPS 140-3 validated modules", strategy="Inventory key specs; confirm vendor PQC support", size_note="", rationale="Managed keys/modules: migration depends on provider support")
    if fam in ("RSA", "ECDSA", "DSA", "EdDSA", "ECDH", "DH", "KEY") or f["asset_type"] == "certificate":
        if purpose in ("key-exchange", "encryption"):
            tgt = "ML-KEM-768"; std = "FIPS 203"
            hyb = "X25519MLKEM768 hybrid key exchange"
        else:
            long_lived = ctx["data_lifetime_years"] >= 15
            tgt = "SLH-DSA-128s" if long_lived else "ML-DSA-65"; std = "FIPS 205" if long_lived else "FIPS 204"
            hyb = "composite/dual signature (classical + ML-DSA)"
        return dict(target=tgt, standard=std, strategy="Hybrid migration: " + hyb if hybrid else "Direct PQC once ecosystem support is confirmed",
                    size_note=SIZES.get(tgt, ""), rationale=f"{fam} used for {purpose}; {'hybrid keeps classical fallback for interoperability' if hybrid else 'lower exposure allows direct switch'}")
    if fam in ("AES",): return dict(target="AES-256-GCM", standard="FIPS 197", strategy="Raise key size if <256", size_note="", rationale="Symmetric: no PQC replacement needed")
    if fam in ("MD5", "SHA-1"): return dict(target="SHA-256 / SHA3-256", standard="FIPS 180-4 / 202", strategy="Replace (classical weakness, not quantum-specific)", size_note="", rationale="Collision-broken hash")
    if fam == "3DES": return dict(target="AES-256-GCM", standard="FIPS 197 / SP 800-38D", strategy="Replace (classical weakness, not quantum-specific)", size_note="", rationale="64-bit block cipher, deprecated")
    return None


def assess(findings, ctx_in, horizon="moderate", weights=None, topo=None):
    w = {**DEFAULT_WEIGHTS, **(weights or {})}
    z = HORIZONS.get(horizon, 15)
    svc_count = {}
    for f in findings:
        if f["asset_type"] in SCORED: svc_count[f["service"]] = svc_count.get(f["service"], 0) + 1
    mx = max(svc_count.values(), default=1)
    dependents = {}
    for s_, ds in (topo or {}).items():
        for d_ in ds: dependents.setdefault(d_, set()).add(s_)
    def trans(s_):
        seen, st = set(), [s_]
        while st:
            for y in dependents.get(st.pop(), ()):
                if y not in seen: seen.add(y); st.append(y)
        return seen
    nsvc = max(len({f["service"] for f in findings}), 2)
    def dep_val(s_): return min(len(trans(s_)) / (nsvc - 1), 1) * 100 if topo else svc_count.get(s_, 0) / mx * 100
    for f in findings:
        if f["asset_type"] not in SCORED:
            f["risk"] = None; continue
        ctx = {**DEFAULT_CTX, **ctx_in.get("default", {}), **ctx_in.get(f["service"], {})}
        if f.get("scope") == "test":  # tests/docs/examples are not production exposure
            ctx = {**ctx, "sensitivity": "low", "criticality": "low", "exposure": "internal", "migration_effort": "low"}
        fam_key = f["algorithm"] if f["algorithm"] in ALGO else f["family"]
        q, note = ALGO.get(fam_key, ALGO.get(f["family"], (0, "n/a")))
        life = f.get("lifetime_years") if f["asset_type"] == "certificate" and ctx.get("data_lifetime_years") is None else ctx["data_lifetime_years"]
        x, y = life, ctx["migration_years"]
        mosca = dict(x=x, y=y, z=z, exposed=bool(x + y > z), margin_years=round(z - (x + y), 1))
        vals = dict(quantum=q, sensitivity=LEVEL.get(ctx["sensitivity"], 50), criticality=LEVEL.get(ctx["criticality"], 50),
                    exposure=100 if ctx["exposure"] == "internet" else 40, lifetime=min(x / 20, 1) * 100,
                    effort=LEVEL.get(ctx["migration_effort"], 50), dependency=dep_val(f["service"]))
        score = round(sum(w[k] * vals[k] for k in w) / sum(w.values()), 1)
        if q >= 90 and mosca["exposed"]: score = max(score, 60)  # Mosca breach => at least HIGH; CRITICAL must be earned by context
        elif q < 30: score = min(score, 34)  # not quantum-relevant
        elif q <= 40: score = min(score, 54)  # classical weakness only
        if f.get("scope") == "test": score = min(score, 54)  # tests/docs never above MEDIUM
        sev = "CRITICAL" if score >= 75 else "HIGH" if score >= 55 else "MEDIUM" if score >= 35 else "LOW"
        if q < 30: sev = "LOW" if q >= 20 or f["family"] in ("AES", "SHA-256") else sev
        f["blocks"] = len(trans(f["service"]))
        f["risk"] = dict(score=score, severity=sev, quantum_note=note, components=vals, mosca=mosca, context=ctx)
        f["recommendation"] = recommend(f, ctx)
    return findings


def plan(findings):
    items = sorted([f for f in findings if f.get("risk") and f["risk"]["severity"] != "LOW"],
                   key=lambda f: ({"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3}[f["risk"]["severity"]], -f.get("blocks", 0), -f["risk"]["score"]))
    phases = {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3}
    return [dict(order=i, id=f["id"], asset=f["algorithm"], service=f["service"], file=f["file"], severity=f["risk"]["severity"],
                 score=f["risk"]["score"], phase=phases[f["risk"]["severity"]], blocks=f.get("blocks", 0), status="todo",
                 target=(f["recommendation"] or {}).get("target"), strategy=(f["recommendation"] or {}).get("strategy"))
            for i, f in enumerate(items, 1)]


def to_cbom(findings, app_name="scanned-app"):
    comps, deps, app_ref, libs = [], [], "app-root", []
    FUNCS = {"signature": ["sign", "verify"], "encryption": ["encrypt", "decrypt"], "key-exchange": ["keyderive"], "hash": ["digest"]}
    QLEVEL = {"AES-128": 1, "AES-192": 3, "AES-256": 5}
    PRIM = {"signature": "signature", "key-exchange": "key-agree", "encryption": "block-cipher", "hash": "hash"}
    for f in findings:
        ref = f"crypto/{f['id']}"
        if f["asset_type"] == "library":
            comps.append({"type": "library", "bom-ref": ref, "name": f["algorithm"], "description": f["purpose"],
                          "evidence": {"occurrences": [{"location": f["file"], "line": f["line"]}]}}); deps.append(ref); libs.append(f); continue
        if f["asset_type"] in ("cloud-service", "hardware-module"):
            comps.append({"type": "service" if f["asset_type"] == "cloud-service" else "device", "bom-ref": ref, "name": f["algorithm"], "description": f["purpose"],
                          "properties": [{"name": "qscan:service", "value": f["service"]}, {"name": "qscan:risk", "value": f["risk"]["severity"] if f.get("risk") else ""}],
                          "evidence": {"occurrences": [{"location": f["file"], "line": l} for l in f.get("lines", [f["line"]])]}}); deps.append(ref); continue
        cp = {"assetType": "certificate" if f["asset_type"] == "certificate" else "related-crypto-material" if f["asset_type"] in ("private-key", "keystore") else "protocol" if f["asset_type"] == "protocol" else "algorithm"}
        if cp["assetType"] == "algorithm":
            cp["algorithmProperties"] = {"primitive": PRIM.get(f["purpose"], "other"), "parameterSetIdentifier": f["key_size"] or "unknown",
                                         "cryptoFunctions": FUNCS.get(f["purpose"], ["other"]),
                                         }
            ql = QLEVEL.get(f["algorithm"], 0 if f["family"] in ("RSA", "ECDSA", "ECDH", "DH", "DSA", "EdDSA") else None)
            if ql is not None: cp["algorithmProperties"]["nistQuantumSecurityLevel"] = ql
        elif cp["assetType"] == "certificate":
            cp["certificateProperties"] = {"subjectName": f.get("subject"), "issuerName": f.get("issuer"),
                                           "notValidBefore": f.get("not_before"), "notValidAfter": f.get("not_after")}
        if f["asset_type"] == "protocol": cp["protocolProperties"] = {"type": f["family"].lower()}
        props = [{"name": "qscan:service", "value": f["service"]}, {"name": "qscan:confidence", "value": str(f["confidence"])}]
        if f.get("risk"): props += [{"name": "qscan:risk", "value": f["risk"]["severity"]}, {"name": "qscan:score", "value": str(f["risk"]["score"])},
                                    {"name": "qscan:recommended-replacement", "value": (f["recommendation"] or {}).get("target", "")}]
        comps.append({"type": "cryptographic-asset", "bom-ref": ref, "name": f["algorithm"], "cryptoProperties": cp,
                      "evidence": {"occurrences": [{"location": f["file"], "line": l} for l in f.get("lines", [f["line"]])]}, "properties": props}); deps.append(ref)
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
            "metadata": {"timestamp": datetime.datetime.utcnow().isoformat() + "Z", "component": {"type": "application", "name": app_name, "bom-ref": app_ref},
                         "tools": {"components": [{"type": "application", "name": "QScan"}]}},
            "components": comps, "dependencies": [{"ref": app_ref, "dependsOn": deps}] + [
                {"ref": f"crypto/{l['id']}", "dependsOn": [f"crypto/{a['id']}" for a in findings if a["asset_type"] in SCORED and a["service"] == l["service"]]}
                for l in libs]}


def run(blob, ctx=None, horizon="moderate", weights=None, name="scanned-app"):
    topo = {}
    raw = scan_zip(blob, topo=topo)
    for k, v in ((ctx or {}).get("deps") or {}).items(): topo.setdefault(k, []); topo[k] += v  # manual deps
    fs = assess(raw, ctx or {}, horizon, weights, topo)
    sev = {}
    for f in fs:
        if f.get("risk"): sev[f["risk"]["severity"]] = sev.get(f["risk"]["severity"], 0) + 1
    scored = [f["risk"]["score"] for f in fs if f.get("risk") and f["scope"] == "prod"]  # readiness = production code only
    readiness = round(100 - (sum(scored) / len(scored) if scored else 0))
    pl = plan(fs)
    return dict(id=uuid.uuid4().hex[:8], summary=dict(total=len(fs), by_severity=sev, readiness=readiness, horizon_years=HORIZONS.get(horizon, 15),
                scored=sum(1 for f in fs if f.get("risk")), prod_quantum_vulnerable=sum(1 for f in fs if f.get("risk") and f["scope"] == "prod" and f["risk"]["components"]["quantum"] >= 90), quantum_vulnerable=sum(1 for f in fs if f.get("risk") and f["risk"]["components"]["quantum"] >= 90)),
                findings=fs, plan=pl, cbom=to_cbom(fs, name), topology=topo)