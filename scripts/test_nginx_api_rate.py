#!/usr/bin/env python3
"""Verify method buckets and the exact scope of the canonical nginx repair."""
import hashlib
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
MAPS = '''    # Dashboard reads use a bounded queue without consuming mutation/login capacity.
    map $request_method $api_write_key {
        default $binary_remote_addr;
        GET "";
        HEAD "";
    }
    map $request_method $api_read_key {
        default "";
        GET $binary_remote_addr;
        HEAD $binary_remote_addr;
    }
    limit_req_zone $api_write_key zone=api_limit:10m rate=60r/m;
    limit_req_zone $api_read_key zone=api_read_limit:10m rate=10r/s;'''


class ApiRateContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = (ROOT / 'infra/nginx/nginx.conf').read_text()

    def test_method_keys_are_exclusive_and_unknown_methods_keep_mutation_limit(self):
        for variable, expected in [('api_write_key', {'default':'$binary_remote_addr', 'GET':'""', 'HEAD':'""'}),
                                   ('api_read_key', {'default':'""', 'GET':'$binary_remote_addr', 'HEAD':'$binary_remote_addr'})]:
            block = re.search(r'map \$request_method \$'+variable+r' \{([^}]+)\}', self.source).group(1)
            entries = dict(re.findall(r'(\S+)\s+(\S+);', block))
            self.assertEqual(expected, entries)
        self.assertIn(MAPS, self.source)

    def test_every_existing_api_limit_location_has_both_bounded_buckets(self):
        blocks = re.findall(r'location ([^{]+)\{([^{}]+)\}', self.source)
        limited = [(path.strip(), body) for path, body in blocks if 'limit_req zone=' in body]
        expected = ['= /api/account/profile-icon', '= /api/gateway/auth/account/profile-icon',
                    '/api/gateway/', '/api/board/', '/api/']
        self.assertCountEqual(expected*2, [path for path, _ in limited])
        for path, body in limited:
            with self.subTest(path=path):
                self.assertEqual(1, body.count('limit_req zone=api_limit burst=20 nodelay;'))
                self.assertEqual(1, body.count('limit_req zone=api_read_limit burst=40 delay=8;'))
                self.assertIn('proxy_pass ', body)
                self.assertNotIn('return ', body)

    def test_rejection_status_and_enforcement_are_not_overridden(self):
        self.assertNotIn('limit_req_status', self.source)
        self.assertNotIn('limit_req_dry_run', self.source)
        self.assertNotIn('error_page', self.source)
        self.assertEqual(2, self.source.count('limit_req_zone '))

    def test_only_approved_rate_directives_change_from_observed_canonical(self):
        original = self.source.replace(MAPS, '    limit_req_zone $binary_remote_addr zone=api_limit:10m rate=60r/m;')
        original = original.replace('            limit_req zone=api_read_limit burst=40 delay=8;\n', '')
        self.assertEqual('f0507d5a8bf0ea90cb6cc722b2dde99c2e049c1d517605adbfe764b39721b5e7',
                         hashlib.sha256(original.encode()).hexdigest())


if __name__ == '__main__':
    unittest.main()
