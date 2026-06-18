import requests
import json
import os
import tomllib
from pathlib import Path

ELASTIC_URL = os.environ.get("ELASTIC_URL")
API_KEY = os.environ.get("API_KEY")

headers = {
    "Content-Type": "application/json",
    "kbn-xsrf": "true",
    "Authorization": f"ApiKey {API_KEY}"
}

def convert_toml_to_rule(toml_data):
    rule = toml_data["rule"]
    return {
        "name": rule["name"],
        "description": rule["description"],
        "severity": rule["severity"],
        "risk_score": 99 if rule["severity"] == "critical" else 73,
        "type": rule["type"],
        "language": rule["language"],
        "index": rule["index"],
        "query": rule["query"].strip(),
        "enabled": True,
        "threat": rule.get("threat", [])
    }

def push_rule(rule):
    response = requests.post(
        f"{ELASTIC_URL}/api/detection_engine/rules",
        headers=headers,
        json=rule
    )
    return response

rules_path = Path("rules")
for toml_file in rules_path.glob("*.toml"):
    with open(toml_file, "rb") as f:
        toml_data = tomllib.load(f)
    
    rule = convert_toml_to_rule(toml_data)
    response = push_rule(rule)
    
    if response.status_code in [200, 201]:
        print(f"✅ Pushed: {rule['name']}")
    else:
        print(f"❌ Failed: {rule['name']} — {response.status_code}")
        print(response.json())
        