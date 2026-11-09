"""Serialize supplied dismissal metadata using the preserved workflow's explicit mapping."""
import json
import re
from pathlib import Path
from urllib.parse import quote

MAPPING = {'not_used': 'vulnerable_code_not_present', 'inaccurate': 'vulnerable_code_not_in_execute_path', 'tolerable_risk': 'inline_mitigations_already_exist'}
README = '''# VEX Statements

This directory contains [OpenVEX](https://openvex.dev/) statements documenting
vulnerabilities that have been assessed and determined to not affect this project.

These statements are auto-generated when Dependabot alerts are dismissed by
maintainers, capturing their security assessment in a machine-readable format.

## Format

Each file is a valid OpenVEX v0.2.0 JSON document that can be consumed by
vulnerability scanners and SBOM tools to reduce false positive alerts for
downstream consumers of this package.
'''

def generate(data, manifest, repository, timestamp):
    required = ['alert_number', 'ghsa_id', 'cve_id', 'package_name', 'package_ecosystem', 'severity', 'summary', 'dismissed_reason']
    if any(not isinstance(data.get(k), str) or not data[k].strip() for k in required):
        raise ValueError('Missing supplied dismissal metadata')
    if not re.fullmatch(r'\d+', data['alert_number']) or not re.fullmatch(r'GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}', data['ghsa_id']):
        raise ValueError('Invalid alert identifier')
    if not re.fullmatch(r'CVE-\d{4}-\d{4,}', data['cve_id']):
        raise ValueError('Invalid CVE identifier')
    reason = data['dismissed_reason']
    if reason == 'no_bandwidth':
        return {'status': 'skip', 'message': 'no_bandwidth dismissals do not represent a security assessment and therefore do not generate VEX statements.'}
    if reason not in MAPPING or data['package_ecosystem'] != 'npm':
        raise ValueError('Unsupported dismissal reason or manifest ecosystem')
    name, version = manifest.get('name'), manifest.get('version')
    if not name or not re.fullmatch(r'\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?', version or ''):
        raise ValueError('Missing npm product identity')
    purl = 'pkg:npm/' + quote(name, safe='/') + '@' + quote(version, safe='.-+')
    doc = {'@context': 'https://openvex.dev/ns/v0.2.0', '@id': f'https://github.com/{repository}/vex/{data["ghsa_id"]}', 'author': 'GitHub Agentic Workflow <vex-generator@github.com>', 'role': 'automated-tool', 'timestamp': timestamp, 'version': 1, 'tooling': 'GitHub Agentic Workflows (gh-aw) VEX Generator', 'statements': [{'vulnerability': {'@id': 'https://github.com/advisories/' + data['ghsa_id'], 'name': data['cve_id'], 'description': data['summary']}, 'products': [{'@id': purl}], 'status': 'not_affected', 'justification': MAPPING[reason], 'impact_statement': f'The supplied maintainer dismissal for {data["package_name"]} ({data["cve_id"]}) is {reason}. This statement records that supplied assessment using the workflow mapping; it does not independently verify exploitability.'}]}
    return {'status': 'generated', 'document': doc, 'path': f'.vex/{data["ghsa_id"]}.json'}

if __name__ == '__main__':
    import datetime
    import os
    data = json.loads(Path('.github/vex/input.json').read_text())
    result = generate(data, json.loads(Path('package.json').read_text()), os.environ['GITHUB_REPOSITORY'], datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00', 'Z'))
    if result['status'] == 'generated':
        import jsonschema
        jsonschema.Draft202012Validator(json.loads(Path('.github/vex/schema.json').read_text()), format_checker=jsonschema.FormatChecker()).validate(result['document'])
        path = Path(result['path'])
        path.parent.mkdir(exist_ok=True)
        if path.exists():
            raise ValueError('Existing statement requires explicit version handling')
        path.write_text(json.dumps(result['document'], indent=2) + '\n')
        if not Path('.vex/README.md').exists():
            Path('.vex/README.md').write_text(README)
    Path('vex-result.json').write_text(json.dumps(result, indent=2) + '\n')

