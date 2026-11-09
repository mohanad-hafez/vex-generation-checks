"""Validate a submitted statement before allowing publication."""
import hashlib
import json
from pathlib import Path

import jsonschema


def read(path):
    return json.loads(Path(path).read_bytes())


path = Path("evidence/statement.json")
data = read("fixed-dispatch.json")
manifest = read("package.json")
document = read(path)
schema = read(".github/vex/schema.json")
jsonschema.Draft202012Validator(
    schema, format_checker=jsonschema.FormatChecker()
).validate(document)
assert len(document["statements"]) == 1
statement = document["statements"][0]
assert statement["vulnerability"]["@id"].split("/")[-1] in {data["ghsa_id"], data["cve_id"]}
assert statement["vulnerability"]["name"] == data["cve_id"]
assert statement["products"] == [{"@id": f"pkg:npm/{manifest['name']}@{manifest['version']}"}]
assert statement["status"] == "not_affected"
assert statement["justification"] == "vulnerable_code_not_present"
assert statement["impact_statement"].strip()
Path("evidence/validated.sha256").write_text(hashlib.sha256(path.read_bytes()).hexdigest() + "\n")
