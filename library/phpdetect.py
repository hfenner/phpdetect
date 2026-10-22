#!/usr/bin/python
"""Read-only Linux PHP evidence collector. Never installs or restarts anything."""
import glob
import json
import os
import platform
import re
import shutil
import subprocess
from datetime import datetime, timezone

CVES = {'CVE-2026-109618', 'CVE-2026-109619'}
# Mappings that are not code on disk: anonymous shared memory, memfd segments, device
# nodes, SysV segments, and application data in temporary locations. They are routinely
# reported as "(deleted)" and say nothing about which PHP build a worker loaded.
PSEUDO_MAPPINGS = ('/memfd:', '/dev/', '/SYSV', '/anon_hugepage', '/[', '/i915', '/drm',
                   '/tmp/', '/var/tmp/', '/run/')


def run(argv):
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=30)
        return p.returncode, p.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return 127, ''


def os_release():
    try:
        return dict(line.strip().split('=', 1) for line in open('/etc/os-release')
                    if '=' in line and not line.startswith('#'))
    except OSError:
        return {}


def is_code_mapping(path):
    return path.startswith('/') and not path.startswith(PSEUDO_MAPPINGS)


def is_elf(path):
    try:
        with open(path, 'rb') as handle:
            return handle.read(4) == b'\x7fELF'
    except OSError:
        return False


def packages():
    if shutil.which('dpkg-query'):
        rc, output = run(['dpkg-query', '-W', '-f=${binary:Package}\t${Version}\t${db:Status-Status}\n'])
        return {p[0]: p[1] for line in output.splitlines()
                if len(p := line.split('\t')) == 3 and p[2] == 'installed'}, rc == 0, 'apt'
    if shutil.which('rpm'):
        rc, output = run(['rpm', '-qa', '--qf', '%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n'])
        return dict(line.split('\t', 1) for line in output.splitlines() if '\t' in line), rc == 0, 'dnf'
    return {}, False, 'unknown'


def processes():
    result, gaps = [], []
    try:
        root = os.stat('/')
        host_root = (root.st_dev, root.st_ino)
    except OSError:
        host_root = None
    for directory in glob.glob('/proc/[0-9]*'):
        try:
            exe = os.readlink(directory + '/exe')
            maps = open(directory + '/maps').read()
            stat = os.stat(directory + '/exe')
            root = os.stat(directory + '/root')
            result.append({'pid': int(directory.rsplit('/', 1)[1]), 'exe': exe,
                           'device': stat.st_dev, 'inode': stat.st_ino, 'maps': maps,
                           # Container and chroot processes see paths relative to another root.
                           'host_ns': (root.st_dev, root.st_ino) == host_root})
        except (FileNotFoundError, ProcessLookupError):
            continue  # Process exited or kernel thread has no executable.
        except (PermissionError, OSError):
            gaps.append('Cannot inspect process ' + directory.rsplit('/', 1)[1])
    return result, gaps


def running_artifact(path, procs):
    """Match executable or mapped module, including replaced/deleted artifacts."""
    path = os.path.realpath(path)
    matches = []
    try:
        disk = os.stat(path)
    except OSError:
        return [], False
    for proc in procs:
        if not proc.get('host_ns', True):
            continue  # Its path namespace differs; it cannot be this host artifact.
        exe = proc['exe'].removesuffix(' (deleted)')
        if exe == path:
            matches.append({'pid': proc['pid'], 'current': proc['exe'] == path and
                            (proc['device'], proc['inode']) == (disk.st_dev, disk.st_ino)})
        for line in proc['maps'].splitlines():
            parts = line.split(None, 5)
            if len(parts) != 6 or parts[5].removesuffix(' (deleted)') != path:
                continue
            major, minor = (int(x, 16) for x in parts[3].split(':'))
            matches.append({'pid': proc['pid'], 'current': parts[5] == path and
                            int(parts[4]) == disk.st_ino and
                            os.makedev(major, minor) == disk.st_dev})
    # Verify mapped libraries too: an updated FPM executable alone is insufficient.
    for match in matches:
        proc = next(p for p in procs if p['pid'] == match['pid'])
        for line in proc['maps'].splitlines():
            parts = line.split(None, 5)
            if len(parts) != 6 or not is_code_mapping(parts[5].removesuffix(' (deleted)')):
                continue
            if parts[5].endswith(' (deleted)'):
                match['current'] = False
                continue
            try:
                mapped = os.stat('/proc/%s/root%s' % (proc['pid'], parts[5]))
                major, minor = (int(x, 16) for x in parts[3].split(':'))
                if mapped.st_ino != int(parts[4]) or mapped.st_dev != os.makedev(major, minor):
                    match['current'] = False
            except OSError:
                match['current'] = False
    unique = {m['pid']: all(x['current'] for x in matches if x['pid'] == m['pid']) for m in matches}
    return [{'pid': pid, 'current': current} for pid, current in unique.items()], bool(unique) and all(unique.values())


def valid_evidence(evidence, release):
    return (bool(evidence.get('advisory_url')) and bool(evidence.get('checked_at')) and
            CVES <= set(evidence.get('cves', [])) and
            str(evidence.get('os_id', '')) == release.get('ID', '').strip('"') and
            str(evidence.get('os_version', '')) == release.get('VERSION_ID', '').strip('"') and
            bool(evidence.get('channel')))


def assess_package(spec, installed, package_ok, procs, proc_gaps, release, owner):
    evidence = spec.get('evidence', {})
    path = spec.get('artifact', '')
    matches, live = running_artifact(path, procs) if path else ([], False)
    required = evidence.get('packages', {})
    exact = bool(required) and all(installed.get(k) == str(v) for k, v in required.items())
    ownership = bool(owner) and owner in required
    status = 'unknown'
    if package_ok and valid_evidence(evidence, release) and exact and ownership:
        if evidence.get('status') == 'affected':
            status = 'affected'
        elif evidence.get('status') == 'patched' and live and not proc_gaps:
            status = 'patched'
    return {'id': spec['id'], 'kind': 'package', 'sites': spec.get('sites', []),
            'exposure': spec.get('exposure', 'unknown'),
            'priority': 'P2' if spec.get('exposure') == 'internal' else 'P1', 'artifact': path,
            'package_owner': owner, 'observed_packages': {k: installed.get(k) for k in required},
            'processes': matches, 'running_build_verified': live and not proc_gaps,
            'patch_status': status, 'evidence': evidence,
            'reason': 'Exact vendor package evidence and live artifact verified' if status == 'patched'
            else 'Affected vendor build' if status == 'affected'
            else 'Missing or mismatched package, vendor, ownership, or running-process evidence'}


def package_owner(path, manager):
    if not path:
        return None
    if manager == 'apt':
        rc, text = run(['dpkg-query', '-S', os.path.realpath(path)])
        if not rc and text:
            return text.split(': /', 1)[0].splitlines()[0]
    if manager == 'dnf':
        rc, text = run(['rpm', '-qf', '--qf', '%{NAME}\n', os.path.realpath(path)])
        if not rc and text:
            return text.splitlines()[0]
    return None


def containers(cli_probe=False):
    if not shutil.which('docker'):
        return [], ['Docker unavailable; container coverage unknown']
    rc, ids = run(['docker', 'ps', '-aq', '--no-trunc'])
    if rc:
        return [], ['Docker inventory inaccessible']
    result = []
    for cid in ids.splitlines():
        rc, raw = run(['docker', 'inspect', cid])
        if rc:
            return result, ['Container inspect failed: ' + cid]
        try:
            item = json.loads(raw)[0]
            php_version = None
            # Opt-in only: this executes a binary from the container image.
            if cli_probe and item['State']['Running']:
                version_rc, version_output = run(['docker', 'exec', cid, 'php', '-n', '-v'])
                found = re.search(r'^PHP ([0-9]+\.[0-9]+\.[0-9]+[^\s]*)', version_output)
                if version_rc == 0 and found:
                    php_version = found.group(1)
            result.append({'id': cid, 'name': item['Name'].lstrip('/'), 'image_id': item['Image'],
                           'image_reference': item['Config']['Image'],
                           'running': item['State']['Running'], 'php_cli_version': php_version,
                           'version_note': ('CLI evidence only; serving runtime unverified' if cli_probe
                                            else 'CLI probe disabled; serving runtime unverified'),
                           'patch_status': 'unknown'})
        except (ValueError, KeyError, IndexError):
            return result, ['Invalid Docker inspect result']
    return result, []


def routing_hints():
    hints = []
    if shutil.which('nginx'):
        # nginx -T emits configuration on stdout; retain routing directives only.
        rc, output = run(['nginx', '-T'])
        if rc == 0:
            hints.extend(line.strip() for line in output.splitlines()
                         if re.match(r'^\s*(server_name|fastcgi_pass|proxy_pass)\s', line)
                         and '@' not in line)  # Do not retain URL credentials.
    for command in ['apachectl', 'apache2ctl', 'httpd']:
        if shutil.which(command):
            rc, output = run([command, '-S'])
            if rc == 0:
                hints.extend(output.splitlines())
            break
    return hints


def collect(specs, cli_probe=False):
    if platform.system() != 'Linux':
        return {'platform': platform.system(), 'patch_status': 'unknown', 'runtimes': [],
                'gaps': ['Automatic host assessment supports Linux only']}
    installed, package_ok, manager = packages()
    procs, proc_gaps = processes()
    release = os_release()
    records = []
    for spec in specs:
        if spec.get('kind', 'package') != 'package':
            records.append({'id': spec['id'], 'kind': spec.get('kind'), 'patch_status': 'unknown',
                            'reason': 'Vendor or container runtime requires dedicated verification'})
            continue
        records.append(assess_package(spec, installed, package_ok, procs, proc_gaps, release,
                                      package_owner(spec.get('artifact'), manager)))
    paths, foreign = set(), set()
    for pattern in ['/usr/bin/php*', '/usr/sbin/php-fpm*', '/usr/local/bin/php*',
                    '/usr/local/sbin/php-fpm*', '/opt/plesk/php/*/sbin/php-fpm',
                    '/opt/cpanel/ea-php*/root/usr/sbin/php-fpm', '/usr/lib/apache2/modules/libphp*.so',
                    '/usr/lib64/httpd/modules/libphp*.so']:
        # Skip wrapper scripts such as phpize and php-config; only binaries can serve requests.
        paths.update(p for p in glob.glob(pattern) if os.path.isfile(p) and is_elf(p))
    for proc in procs:
        target = paths if proc.get('host_ns', True) else foreign
        if 'php' in proc['exe'].lower():
            target.add(proc['exe'].removesuffix(' (deleted)'))
        for line in proc['maps'].splitlines():
            parts = line.split(None, 5)
            if len(parts) == 6 and parts[5].startswith('/') and 'php' in parts[5].lower():
                target.add(parts[5].removesuffix(' (deleted)'))
    configured = {os.path.realpath(s['artifact']) for s in specs if s.get('artifact')}
    candidates = [{'artifact': p, 'patch_status': 'unknown', 'reason': 'Unmapped PHP candidate'}
                  for p in sorted(paths) if os.path.realpath(p) not in configured]
    candidates += [{'artifact': p, 'patch_status': 'unknown',
                    'reason': 'PHP candidate inside a container or chroot; path is relative to that root'}
                   for p in sorted(foreign)]
    docker, docker_gaps = containers(cli_probe)
    # A host cannot be cleared merely because the configured subset is patched.
    return {'platform': 'Linux', 'os_release': release, 'package_manager': manager,
            'php_packages': {k: v for k, v in installed.items() if 'php' in k.lower()},
            'runtimes': records, 'unmapped_candidates': candidates, 'containers': docker,
            'routing_hints': routing_hints(),
            'gaps': proc_gaps + docker_gaps + ([] if package_ok else ['Package database unavailable']),
            'patch_status': 'affected' if any(r['patch_status'] == 'affected' for r in records) else 'unknown',
            'scope_note': 'Per-runtime results do not prove complete host or container coverage',
            'collected_at': datetime.now(timezone.utc).isoformat()}


def main():
    from ansible.module_utils.basic import AnsibleModule
    module = AnsibleModule(argument_spec={'runtimes': {'type': 'list', 'elements': 'dict', 'default': []},
                                          'container_cli_probe': {'type': 'bool', 'default': False}},
                           supports_check_mode=True)
    try:
        module.exit_json(changed=False, report=collect(module.params['runtimes'],
                                                       module.params['container_cli_probe']))
    except Exception as exc:
        module.exit_json(changed=False, report={'patch_status': 'unknown', 'runtimes': [],
                                               'gaps': [str(exc)]})


if __name__ == '__main__':
    main()
