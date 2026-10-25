import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('configure_hosting', ROOT / 'scripts' / 'configure-hosting.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class HostingConfigurationTests(unittest.TestCase):
    def source(self, parent):
        source = parent / 'source'
        source.mkdir()
        (source / 'index.html').write_text('<html><meta http-equiv="Content-Security-Policy" content="default-src \'self\'; script-src \'self\'; connect-src \'self\' https://old.example; base-uri \'none\'"></html>', encoding='utf-8')
        (source / 'shortlink-config.mjs').write_text('unchanged original', encoding='utf-8')
        (source / 'manifest.webmanifest').write_text(json.dumps({'id': './', 'start_url': './', 'scope': './', 'icons': [{'src': 'icon.png'}]}), encoding='utf-8')
        (source / 'sw.js').write_text('const VERSION=10;', encoding='utf-8')
        (source / 'icon.png').write_bytes(b'fixture')
        return source

    def test_prepares_isolated_release_and_preserves_original(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); source = self.source(root)
            before = {p.name: p.read_bytes() for p in source.iterdir()}
            result = module.prepare(source, root / 'release', 'https://viewer.example/pso/', 'https://api.example/functions/v1/')
            self.assertEqual(before, {p.name: p.read_bytes() for p in source.iterdir()})
            text = (result / 'docs' / 'shortlink-config.mjs').read_text()
            for route in module.ENDPOINTS.values():
                self.assertIn('https://api.example/functions/v1/' + route, text)
            page = (result / 'docs' / 'index.html').read_text()
            self.assertIn('https://api.example', page); self.assertNotIn('https://old.example', page)
            self.assertIn('script-src', page); self.assertIn('base-uri', page)
            self.assertNotIn('frame-ancestors', page)
            self.assertIn("frame-ancestors 'none'", (result / 'security-headers.txt').read_text())
            settings = json.loads((result / 'service-config.json').read_text())
            self.assertEqual(settings['viewer_url'], 'https://viewer.example/pso/')
            self.assertEqual(set(settings), {'viewer_url', 'team_endpoint', 'direct_endpoint'})
            self.assertEqual(json.loads((result / 'docs' / 'manifest.webmanifest').read_text())['scope'], './')

    def test_rejects_credentials_injection_paths_and_non_https(self):
        for address in ['http://viewer.example/', 'https://user:pass@viewer.example/', 'https://viewer.example/?token=x', 'https://viewer.example/#key', 'https://viewer.example/a/../', 'https://viewer.example/%2e%2e/', 'https://viewer.example/a b/', 'https://viewer.example:0/', 'https://viewer.example:99999/', 'https://a\'b.example/']:
            with self.subTest(address=address):
                self.assertRaises(ValueError, module.https_base, address)
        self.assertEqual(module.https_base('https://VIEWER.example:443/pso'), 'https://viewer.example/pso/')

    def test_never_overwrites_output_or_writes_inside_source(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); source = self.source(root)
            output = root / 'release'; output.mkdir(); (output / 'keep').write_text('kept')
            for target in [output, source, source / 'new']:
                self.assertRaises(ValueError, module.prepare, source, target, 'https://viewer.example/', 'https://api.example/')
            self.assertEqual((output / 'keep').read_text(), 'kept')

    def test_rejects_symlinks_or_missing_csp_without_partial_output(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); source = self.source(root)
            (source / 'secret').symlink_to(root / 'outside')
            self.assertRaises(ValueError, module.prepare, source, root / 'release', 'https://viewer.example/', 'https://api.example/')
            (source / 'secret').unlink(); (source / 'index.html').write_text('<html></html>')
            self.assertRaises(ValueError, module.prepare, source, root / 'release', 'https://viewer.example/', 'https://api.example/')
            self.assertFalse((root / 'release').exists())


if __name__ == '__main__':
    unittest.main()
