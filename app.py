import json, pathlib
from fastapi import FastAPI, File, Form, UploadFile, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
import core

app = FastAPI(title="QScan")
SCANS = {}  # in-memory store (prototype)
HERE = pathlib.Path(__file__).parent
DIST = HERE / "frontend" / "dist"


@app.post("/api/scan")
async def scan(file: UploadFile = File(...), context: str = Form("{}"), horizon: str = Form("moderate"), weights: str = Form("{}")):
    blob = await file.read()
    if len(blob) > 50_000_000: raise HTTPException(413, "ZIP too large")
    try:
        res = core.run(blob, json.loads(context or "{}"), horizon, json.loads(weights or "{}"), file.filename)
    except Exception as e:
        raise HTTPException(400, f"Scan failed: {e}")
    SCANS[res["id"]] = res
    return res


@app.get("/api/cbom/{sid}")
def cbom(sid: str):
    if sid not in SCANS: raise HTTPException(404)
    return JSONResponse(SCANS[sid]["cbom"], headers={"Content-Disposition": f"attachment; filename=cbom-{sid}.json"})


if DIST.exists():  # production: serve the built React app
    app.mount("/", StaticFiles(directory=DIST, html=True), name="ui")
else:  # fallback: the legacy single-file dashboard
    @app.get("/")
    def index():
        return FileResponse(HERE / "index.html")