import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('phpdetect', Path(__file__).parents[1] / 'library/phpdetect.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class AssessmentTests(unittest.TestCase):
    def setUp(self):
        self.file = tempfile.NamedTemporaryFile()
        self.disk = os.stat(self.file.name)
        self.proc = {'pid': 123, 'exe': os.path.realpath(self.file.name), 'device': self.disk.st_dev,
                     'inode': self.disk.st_ino, 'maps': ''}
        self.release = {'ID': 'ubuntu', 'VERSION_ID': '24.04'}
        self.runtime = {'id': 'test', 'artifact': self.file.name,
                        'evidence': {'status': 'patched', 'advisory_url': 'https://vendor/advisory',
                                     'checked_at': '2026-10-22T12:00:00Z', 'cves': sorted(m.CVES),
                                     'os_id': 'ubuntu', 'os_version': '24.04', 'channel': 'security',
                                     'packages': {'php-fpm': '8.3.6-vendor-fix'}}}

    def tearDown(self):
        self.file.close()

    def assess(self, **kwargs):
        params = dict(spec=self.runtime, installed={'php-fpm': '8.3.6-vendor-fix'}, package_ok=True,
                      procs=[self.proc], proc_gaps=[], release=self.release, owner='php-fpm')
        params.update(kwargs)
        return m.assess_package(**params)['patch_status']

    def test_exact_backport_and_running_artifact(self):
        self.assertEqual(self.assess(), 'patched')

    def test_old_package_is_unknown_without_affected_advisory(self):
        self.assertEqual(self.assess(installed={'php-fpm': '8.3.6-old'}), 'unknown')

    def test_missing_worker(self):
        self.assertEqual(self.assess(procs=[]), 'unknown')

    def test_replaced_worker(self):
        self.proc['inode'] += 1
        self.assertEqual(self.assess(), 'unknown')

    def test_deleted_worker(self):
        self.proc['exe'] += ' (deleted)'
        self.assertEqual(self.assess(), 'unknown')

    def test_one_stale_replica_prevents_clearance(self):
        stale = dict(self.proc, pid=456, inode=0)
        self.assertEqual(self.assess(procs=[self.proc, stale]), 'unknown')

    def test_deleted_library_prevents_clearance(self):
        self.proc['maps'] = '0-1 r--p 0 00:00 123 /lib/libphp.so (deleted)'
        self.assertEqual(self.assess(), 'unknown')

    def test_pseudo_memory_mappings_do_not_block(self):
        self.proc['maps'] = '\n'.join(['0-1 rw-s 0 00:01 7 /memfd:opcache (deleted)',
                                       '0-1 rw-s 0 00:05 5 /dev/zero (deleted)',
                                       '0-1 rw-s 0 00:01 9 /SYSV00000000 (deleted)'])
        self.assertEqual(self.assess(), 'patched')

    def test_container_process_with_same_path_is_ignored(self):
        foreign = dict(self.proc, pid=456, inode=0, host_ns=False)
        self.assertEqual(self.assess(procs=[self.proc, foreign]), 'patched')

    def test_only_container_process_cannot_clear_host_artifact(self):
        self.assertEqual(self.assess(procs=[dict(self.proc, host_ns=False)]), 'unknown')

    def test_integer_os_version_from_yaml(self):
        self.runtime['evidence']['os_version'] = 12
        self.assertEqual(self.assess(release={'ID': 'ubuntu', 'VERSION_ID': '12'}), 'patched')

    def test_unreadable_processes(self):
        self.assertEqual(self.assess(proc_gaps=['permission denied']), 'unknown')

    def test_missing_cve(self):
        self.runtime['evidence']['cves'].pop()
        self.assertEqual(self.assess(), 'unknown')

    def test_wrong_os(self):
        self.assertEqual(self.assess(release={'ID': 'debian', 'VERSION_ID': '13'}), 'unknown')

    def test_wrong_package_owner(self):
        self.assertEqual(self.assess(owner='other-php'), 'unknown')

    def test_vendor_affected_evidence(self):
        self.runtime['evidence']['status'] = 'affected'
        self.assertEqual(self.assess(), 'affected')

    def test_non_linux_cannot_be_cleared(self):
        with patch.object(m.platform, 'system', return_value='Darwin'):
            self.assertEqual(m.collect([])['patch_status'], 'unknown')

    def test_no_php_does_not_prove_host_safe(self):
        with patch.object(m.platform, 'system', return_value='Linux'), \
             patch.object(m, 'packages', return_value=({}, True, 'apt')), \
             patch.object(m, 'processes', return_value=([], [])), \
             patch.object(m, 'containers', return_value=([], [])), \
             patch.object(m, 'routing_hints', return_value=[]), \
             patch.object(m.glob, 'glob', return_value=[]):
            self.assertEqual(m.collect([])['patch_status'], 'unknown')


if __name__ == '__main__':
    unittest.main()
