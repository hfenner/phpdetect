#!/usr/bin/env python3
"""Bundle NCSC's product lists from one Git commit; never execute upstream code."""
import json
from pathlib import Path
import re
import subprocess
import tempfile

SOURCE = 'https://github.com/NCSC-NL/php2shell'
DESTINATION = Path(__file__).resolve().parents[1] / 'data/ncsc/snapshot.json'


def git(repository, *args):
    return subprocess.check_output(['git', '-C', str(repository), *args], text=True)


def build_snapshot(repository):
    commit = git(repository, 'rev-parse', 'HEAD').strip()
    paths = sorted(p for p in git(repository, 'ls-tree', '-r', '--name-only', commit).splitlines()
                   if re.fullmatch(r'software/software_list[^/]*\.md', p))
    if not paths:
        raise ValueError('No NCSC product lists found; keeping the previous snapshot')
    pages = []
    for path in paths:
        content = git(repository, 'show', f'{commit}:{path}')
        if not content.strip():
            raise ValueError(f'Empty product list: {path}')
        pages.append({'path': path, 'content': content, 'status': 200})
    return {'source': SOURCE, 'commit_sha': commit,
            'commit_date': git(repository, 'show', '-s', '--format=%cI', commit).strip(),
            'license': git(repository, 'show', f'{commit}:LICENSE'), 'pages': pages}


def write_snapshot(snapshot, destination):
    content = json.dumps(snapshot, ensure_ascii=False, indent=2) + '\n'
    if destination.exists() and destination.read_text(encoding='utf-8') == content:
        return False
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=destination.parent,
                                     delete=False) as output:
        temporary = Path(output.name)
        try:
            output.write(content)
            output.flush()
            temporary.chmod(0o644)
            temporary.replace(destination)
        finally:
            temporary.unlink(missing_ok=True)
    return True


def main():
    with tempfile.TemporaryDirectory(prefix='phpdetect-ncsc-') as directory:
        subprocess.run(['git', 'clone', '--quiet', '--depth', '1', '--branch', 'main',
                        SOURCE + '.git', directory], check=True, timeout=120)
        snapshot = build_snapshot(directory)
    changed = write_snapshot(snapshot, DESTINATION)
    print(f'NCSC {snapshot["commit_sha"]}: {"updated" if changed else "unchanged"}')


if __name__ == '__main__':
    main()
