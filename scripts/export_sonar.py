#!/usr/bin/env python3
"""Export SonarQube issues + security hotspots to evidence/static/sonar-issues.json
(consumed by report/generate_static_report.py). Needs SONAR_TOKEN; SONAR_URL defaults to localhost."""
import base64, json, os, urllib.request
URL = os.environ.get("SONAR_URL", "http://localhost:9000"); KEY = os.environ.get("SONAR_PROJECT", "aes-lab")
auth = "Basic " + base64.b64encode((os.environ["SONAR_TOKEN"] + ":").encode()).decode()
def get(path):
    r = urllib.request.Request(URL + path, headers={"Authorization": auth})
    return json.load(urllib.request.urlopen(r))
out = {"issues": get(f"/api/issues/search?componentKeys={KEY}&ps=500")["issues"],
       "hotspots": get(f"/api/hotspots/search?projectKey={KEY}&ps=500")["hotspots"],
       "server": get("/api/server/version") if False else URL}
os.makedirs("evidence/static", exist_ok=True)
json.dump(out, open("evidence/static/sonar-issues.json", "w"), indent=2)
print(len(out["issues"]), "issues,", len(out["hotspots"]), "hotspots exported")
