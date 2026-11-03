import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tomllib

policy = json.loads(Path('security/review-policy.json').read_text())
assert hashlib.sha256(Path('Cargo.lock').read_bytes()).hexdigest() == policy['cargo_lock_sha256']
tree = subprocess.check_output([
    'cargo', '+1.91.0', 'tree', '--locked', '--offline',
    '--target', 'aarch64-apple-darwin', '-p', 'agent-desktop',
    '-p', 'agent-desktop-macos', '--edges', 'normal,build',
], text=True)
expected = {(p['name'], p['version']): p for p in policy['active_crates']}
actual = set(re.findall(r'([\w-]+) v([0-9][\w.+-]*)', tree))
actual = {p for p in actual if not p[0].startswith('agent-desktop')}
assert actual == set(expected), (actual - set(expected), set(expected) - actual)
host_tree = subprocess.check_output([
    'cargo', '+1.91.0', 'tree', '--locked', '--offline',
    '--target', 'x86_64-apple-darwin', '-p', 'agent-desktop',
    '-p', 'agent-desktop-macos', '--edges', 'normal,build',
], text=True)
host_crates = set(re.findall(r'([\w-]+) v([0-9][\w.+-]*)', host_tree))
host_crates = {p for p in host_crates if not p[0].startswith('agent-desktop')}
assert host_crates == set(expected), 'unreviewed Intel-host dependency graph'
registry = Path(os.environ['CARGO_HOME']) / 'registry'
index = next((registry / 'index').glob('*/.cache'))
sources = next((registry / 'src').glob('*'))
cache = next((registry / 'cache').glob('*'))
cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=7)
scripts = {}
results = []
for (name, version), record in sorted(expected.items()):
    if len(name) == 1:
        key = '1/' + name
    elif len(name) == 2:
        key = '2/' + name
    elif len(name) == 3:
        key = '3/' + name[0] + '/' + name
    else:
        key = name[:2] + '/' + name[2:4] + '/' + name
    entries = (index / key).read_bytes().split(b'\0')
    entry = next(json.loads(p) for p in entries if p.startswith(b'{') and json.loads(p)['vers'] == version)
    assert not entry['yanked'], (name, version, 'yanked')
    assert entry['cksum'] == record['checksum'], (name, version, 'index checksum')
    published = datetime.datetime.fromisoformat(entry['pubtime'].replace('Z', '+00:00'))
    assert published <= cutoff, (name, version, 'less than seven days old')
    archive = cache / f'{name}-{version}.crate'
    assert hashlib.sha256(archive.read_bytes()).hexdigest() == record['checksum']
    source = sources / f'{name}-{version}'
    checksums = json.loads((source / '.cargo-checksum.json').read_text())
    for relative, digest in checksums['files'].items():
        file = source / relative
        assert file.resolve().is_relative_to(source.resolve())
        assert hashlib.sha256(file.read_bytes()).hexdigest() == digest, (name, relative)
    manifest = tomllib.loads((source / 'Cargo.toml').read_text())
    build = manifest['package'].get('build')
    if build or (source / 'build.rs').exists():
        script = source / (build or 'build.rs')
        assert script.resolve().is_relative_to(source.resolve())
        scripts[f'{name} {version}'] = hashlib.sha256(script.read_bytes()).hexdigest()
    results.append({'name': name, 'version': version, 'published': entry['pubtime'], 'checksum': entry['cksum']})
scripts['project'] = hashlib.sha256(Path('crates/macos/build.rs').read_bytes()).hexdigest()
assert scripts == policy['build_script_sha256'], 'build scripts changed or new scripts appeared'
Path('dist').mkdir(exist_ok=True)
Path('dist/dependency-verification.json').write_text(json.dumps({
    'checked_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
    'upstream_commit': policy['upstream_commit'],
    'cargo_lock_sha256': policy['cargo_lock_sha256'],
    'build_scripts': scripts,
    'crates': results,
}, indent=2) + '\n')
print(f'PASS: {len(results)} native dependencies; seven-day age, yank state, source checksums, reviewed build scripts')
