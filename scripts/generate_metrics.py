import tomllib
import json
import csv
from pathlib import Path

rules_path = Path("rules")
rules = []

for toml_file in rules_path.glob("*.toml"):
    with open(toml_file, "rb") as f:
        toml_data = tomllib.load(f)
    
    rule = toml_data["rule"]
    threat = rule.get("threat", [])
    
    techniques = []
    for t in threat:
        for technique in t.get("technique", []):
            techniques.append(technique["id"])
            for sub in technique.get("subtechnique", []):
                techniques.append(sub["id"])
    
    rules.append({
        "name": rule["name"],
        "severity": rule["severity"],
        "index": ", ".join(rule["index"]),
        "techniques": ", ".join(techniques),
        "query": rule["query"].strip()
    })

# Generate CSV
with open("metrics/rules.csv", "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=["name", "severity", "index", "techniques", "query"])
    writer.writeheader()
    writer.writerows(rules)
print("✅ Generated metrics/rules.csv")

# Generate Markdown
with open("metrics/rules.md", "w") as f:
    f.write("# Detection Rules\n\n")
    f.write("| Rule Name | Severity | MITRE Techniques |\n")
    f.write("|---|---|---|\n")
    for rule in rules:
        f.write(f"| {rule['name']} | {rule['severity']} | {rule['techniques']} |\n")
print("✅ Generated metrics/rules.md")

# Generate ATT&CK Navigator JSON
techniques_list = []
for rule in rules:
    for technique in rule["techniques"].split(", "):
        if technique:
            techniques_list.append({
                "techniqueID": technique,
                "color": "#ff6666",
                "comment": rule["name"],
                "enabled": True
            })

navigator = {
    "name": "Detection Coverage",
    "versions": {"attack": "14", "navigator": "4.9"},
    "domain": "enterprise-attack",
    "techniques": techniques_list
}

with open("metrics/navigator.json", "w") as f:
    json.dump(navigator, f, indent=2)
print("✅ Generated metrics/navigator.json")