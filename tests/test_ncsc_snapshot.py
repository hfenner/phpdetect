import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location(
    'update_ncsc_snapshot', Path(__file__).parents[1] / 'scripts/update_ncsc_snapshot.py')
updater = importlib.util.module_from_spec(spec)
spec.loader.exec_module(updater)


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / 'upstream'
        self.repo.mkdir()
        self.git('init', '-q')
        self.git('config', 'user.name', 'Test')
        self.git('config', 'user.email', 'test@example.invalid')
        (self.repo / 'LICENSE').write_text('Test license\n')
        (self.repo / 'software').mkdir()
        (self.repo / 'software/software_list_a.md').write_text('| Example product | unknown |\n')
        (self.repo / 'software/README.md').write_text('Not a product list')
        self.commit()

    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.repo), *args], text=True)

    def commit(self):
        self.git('add', '.')
        self.git('commit', '-qm', 'fixture')

    def test_snapshot_uses_committed_lists_and_provenance(self):
        (self.repo / 'software/software_list_a.md').write_text('Uncommitted data')
        snapshot = updater.build_snapshot(self.repo)
        self.assertEqual(snapshot['commit_sha'], self.git('rev-parse', 'HEAD').strip())
        self.assertEqual(snapshot['license'], 'Test license\n')
        self.assertEqual(snapshot['pages'], [{'path': 'software/software_list_a.md',
                                           'content': '| Example product | unknown |\n', 'status': 200}])

    def test_unchanged_refresh_does_not_rewrite_snapshot(self):
        output = self.root / 'snapshot.json'
        snapshot = updater.build_snapshot(self.repo)
        self.assertTrue(updater.write_snapshot(snapshot, output))
        before = output.stat().st_mtime_ns
        self.assertFalse(updater.write_snapshot(snapshot, output))
        self.assertEqual(output.stat().st_mtime_ns, before)
        self.assertEqual(json.loads(output.read_text()), snapshot)

    def test_missing_lists_preserve_previous_snapshot(self):
        output = self.root / 'snapshot.json'
        updater.write_snapshot(updater.build_snapshot(self.repo), output)
        before = output.read_bytes()
        (self.repo / 'software/software_list_a.md').unlink()
        self.commit()
        with self.assertRaisesRegex(ValueError, 'No NCSC product lists'):
            updater.write_snapshot(updater.build_snapshot(self.repo), output)
        self.assertEqual(output.read_bytes(), before)

    def test_empty_list_rejected(self):
        (self.repo / 'software/software_list_a.md').write_text('')
        self.commit()
        with self.assertRaisesRegex(ValueError, 'Empty product list'):
            updater.build_snapshot(self.repo)
