"""Static compatibility checker for the CIPHER vanilla frontend and FastAPI backend.
It intentionally does not import the backend so it can run before dependencies are installed.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "python_backend" / "main.py"
FRONTEND = ROOT / "frontend" / "script.js"


def normalize(path: str) -> str:
    path = path.split("?")[0]
    path = re.sub(r"\$\{[^}]+\}", "{param}", path)
    path = re.sub(r"\{[^}]+\}", "{param}", path)
    if not path.startswith("/"):
        path = "/" + path
    return path


def route_shapes() -> set[str]:
    tree = ast.parse(BACKEND.read_text(encoding="utf-8"), filename=str(BACKEND))
    routes: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for dec in node.decorator_list:
                if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute):
                    if dec.func.attr in {"get", "post", "put", "patch", "delete", "api_route"} and dec.args:
                        arg = dec.args[0]
                        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                            routes.add(normalize(arg.value))
    return routes


def frontend_paths() -> set[str]:
    text = FRONTEND.read_text(encoding="utf-8", errors="ignore")
    found: set[str] = set()
    # Handles fetch('/x'), fetch(`/x/${id}`), and concatenation starts.
    for match in re.finditer(r"fetch\s*\(\s*([`\"'])(/[^`\"']*)\1", text):
        found.add(normalize(match.group(2)))
    return found


def find_matches(path: str, routes: set[str]) -> bool:
    if path in routes:
        return True
    # Replace parameterized path segments by placeholders and compare segment count.
    ps = path.split("/")
    for route in routes:
        rs = route.split("/")
        if len(ps) != len(rs):
            continue
        ok = True
        for a, b in zip(ps, rs):
            if a == "{param}" or b == "{param}":
                continue
            if a != b:
                ok = False
                break
        if ok:
            return True
    return False


if __name__ == "__main__":
    routes = route_shapes()
    calls = frontend_paths()
    missing = sorted(p for p in calls if not find_matches(p, routes))
    print(f"Backend route shapes: {len(routes)}")
    print(f"Frontend fetch paths: {len(calls)}")
    if missing:
        print("MISSING BACKEND ROUTES:")
        for p in missing:
            print(f"  - {p}")
        raise SystemExit(1)
    print("All statically detected frontend fetch paths have a backend route.")
