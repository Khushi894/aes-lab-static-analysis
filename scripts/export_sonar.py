#!/usr/bin/env python3
"""Export SonarQube issues + security hotspots to evidence/static/sonar-issues.json"""
import base64, json, os, sys, urllib.error, urllib.request

URL = os.environ.get("SONAR_URL", "http://localhost:9000")
KEY = os.environ.get("SONAR_PROJECT", "aes-lab")
auth = "Basic " + base64.b64encode((os.environ["SONAR_TOKEN"] + ":").encode()).decode()


def get(path):
    r = urllib.request.Request(URL + path, headers={"Authorization": auth})
    try:
        return json.load(urllib.request.urlopen(r))
    except urllib.error.HTTPError as e:
        sys.exit(f"HTTP {e.code} for {path}\n{e.read().decode(errors='replace')}")


def hotspots():
    for param in ("project", "projectKey"):
        try:
            r = urllib.request.Request(f"{URL}/api/hotspots/search?{param}={KEY}&ps=500", headers={"Authorization": auth})
            return json.load(urllib.request.urlopen(r))["hotspots"]
        except urllib.error.HTTPError as e:
            last = f"HTTP {e.code} with '{param}': {e.read().decode(errors='replace')}"
    sys.exit(last)


out = {"issues": get(f"/api/issues/search?componentKeys={KEY}&ps=500")["issues"], "hotspots": hotspots(), "server": URL}
os.makedirs("evidence/static", exist_ok=True)
json.dump(out, open("evidence/static/sonar-issues.json", "w"), indent=2)
print(len(out["issues"]), "issues,", len(out["hotspots"]), "hotspots exported")
