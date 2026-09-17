"""Local end-to-end smoke test for the CIPHER Python backend."""
import os, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DB = ROOT / ".cipher_smoke.db"
os.environ["CIPHER_DB_FILE"] = str(DB)
os.environ["SEED_DEMO_DATA"] = "true"
os.environ["SECRET_KEY"] = "smoke-test-secret"
os.environ.pop("DATABASE_URL", None)
os.environ["NEO4J_REQUIRED_FOR_GRAPH"] = "false"
sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient
from python_backend.main import app

client = TestClient(app)

def check(r, name, allowed=(200, 201)):
    if r.status_code not in allowed:
        raise RuntimeError(f"{name} failed: HTTP {r.status_code}: {r.text[:500]}")
    return r.json() if r.content else {}

try:
    check(client.get("/api/health"), "health")
    check(client.get("/api/db-test"), "db-test")
    login = check(client.post("/api/auth/login", json={"email": "investigator@cipher.local", "password": "cipher"}), "login")
    token = login["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    cases = check(client.get("/api/cases", headers=headers), "cases")
    case_id = cases["cases"][0]["id"]
    # Master CSV import
    master = ROOT / "samples" / "CIPHER_complete_case_master_single_CSV.csv"
    with master.open("rb") as fh:
        imported = check(client.post(f"/api/cases/{case_id}/import-master-csv", headers=headers, files={"file": (master.name, fh, "text/csv")}), "master csv import")
    result = imported["import"]
    expected = {"nodes":26,"relationships":33,"evidence":6,"locations":5,"observations":7,"events":9,"review_queue":8,"audit_log":6,"ai_test_issues":4,"test_cases":20,"skipped":0}
    for k,v in expected.items():
        if result.get(k) != v:
            raise RuntimeError(f"master CSV {k}: expected {v}, got {result.get(k)}")
    # Core read endpoints
    for path in [f"/api/cases/{case_id}/entities", f"/api/cases/{case_id}/relationships", f"/api/cases/{case_id}/locations", f"/api/cases/{case_id}/gis-data", f"/api/cases/{case_id}/graph", f"/api/cases/{case_id}/timeline", f"/api/cases/{case_id}/review", f"/api/cases/{case_id}/audit", f"/api/cases/{case_id}/diagnostics", "/api/ai/cases"]:
        check(client.get(path, headers=headers), path)
    reviews = check(client.get(f"/api/cases/{case_id}/review", headers=headers), "review")
    if reviews["count"]:
        review_id = reviews["items"][0]["id"]
        check(client.post(f"/api/review/{review_id}/accept", headers=headers, json={"review_note":"Smoke test"}), "review accept")
    # Create and link manual nodes
    a = check(client.post(f"/api/cases/{case_id}/entities", headers=headers, json={"label":"Smoke Person","entity_type":"person","verification_status":"verified"}), "entity create")
    b = check(client.post(f"/api/cases/{case_id}/entities", headers=headers, json={"label":"Smoke Phone","entity_type":"phone","verification_status":"verified"}), "entity create 2")
    check(client.post(f"/api/cases/{case_id}/relationships", headers=headers, json={"source_entity_id":a["entity"]["id"],"target_entity_id":b["entity"]["id"],"relationship_type":"USES_PHONE","verification_status":"verified"}), "relationship create")
    # Protected endpoint without token must reject.
    if client.get(f"/api/cases/{case_id}/entities").status_code != 401:
        raise RuntimeError("protected endpoint did not reject unauthenticated request")
    print("CIPHER PYTHON BACKEND SMOKE TEST: PASS")
finally:
    try:
        DB.unlink(missing_ok=True)
    except Exception:
        pass
