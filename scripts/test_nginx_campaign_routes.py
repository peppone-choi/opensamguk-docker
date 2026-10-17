#!/usr/bin/env python3
"""Check nginx's campaign routing boundary without Docker or application secrets."""

from pathlib import Path
import re
import unittest
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[1]
# Actual page roots at app main eb74c531a9768474d6f24e3ca6200df6a8e84d67.
# Route groups such as (campaign) do not appear in browser URLs.
APP_PAGE_ROOTS = {
    "admin", "battle-replay", "corps", "council", "court", "create",
    "generals", "help", "history", "join", "mail", "my", "my-cities",
    "my-generals", "rankings", "records", "register", "retinue",
    "stratagem", "territory",
}


def routes(pattern):
    return set(pattern.split("|"))


class CampaignRouteContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = (ROOT / "infra/nginx/nginx.conf").read_text()
        cls.path_routes = routes(re.search(
            r'~\^/game/\(\?:([^\n]+?)\)\(\?:/\|\$\) "";', cls.source,
        ).group(1))
        cls.cookie_routes = routes(re.search(
            r'~\^\(\?:([^\n]+?)\)\$ "";', cls.source,
        ).group(1))
        cls.locations = [routes(match) for match in re.findall(
            r'location ~ \^/game/\(\?:([^\n]+?)\)\(\?:/\|\$\) \{', cls.source,
        )]
        reserved_map = re.search(
            r'var reservedGameRouteIDs = map\[string\]struct\{\}\{(.*?)\n\}',
            (ROOT / "deployer/main.go").read_text(), re.S,
        ).group(1)
        cls.deployer_routes = set(re.findall(r'"([^"\n]+)"\s*:', reserved_map))

    def test_actual_app_page_roots_are_reserved_everywhere(self):
        self.assertEqual(len(self.locations), 2, "HTTP and HTTPS locations required")
        for name, found in [
            ("path map", self.path_routes), ("cookie map", self.cookie_routes),
            ("deployer", self.deployer_routes),
            *[(f"location {index}", value) for index, value in enumerate(self.locations)],
        ]:
            with self.subTest(surface=name):
                self.assertFalse(APP_PAGE_ROOTS - found, f"missing {sorted(APP_PAGE_ROOTS - found)}")

    def test_reservation_sets_stay_consistent(self):
        self.assertEqual(self.path_routes, self.deployer_routes | {"all"})
        self.assertEqual(self.cookie_routes, self.path_routes)
        for found in self.locations:
            self.assertEqual(found, self.deployer_routes)

    def test_cookie_gated_locations_preserve_uri_and_query(self):
        blocks = re.findall(
            r'location ~ \^/game/\(\?:[^\n]+\)\(\?:/\|\$\) \{(.*?)\n        \}',
            self.source, re.S,
        )
        self.assertEqual(len(blocks), 2)
        for block in blocks:
            self.assertIn('if ($game_cookie_web_upstream = "")', block)
            self.assertIn('return 404;', block)
            # No replacement URI: Next receives /game/<page> and the original query.
            self.assertIn('proxy_pass $game_cookie_web_upstream;', block)
            self.assertNotIn('rewrite ', block)

    def test_campaign_paths_cannot_be_interpreted_as_server_ids(self):
        for scheme in ("http", "https"):
            for page in sorted(APP_PAGE_ROOTS):
                for suffix in ("", "/", "/detail?slot=1&next=%2Fgame%2Fhelp"):
                    with self.subTest(scheme=scheme, page=page, suffix=suffix):
                        path = urlsplit(f"{scheme}://localhost/game/{page}{suffix}").path
                        root = path.split("/")[2]
                        self.assertIn(root, self.path_routes)
                        self.assertTrue(all(root in location for location in self.locations))

    def test_cookie_and_path_ids_remain_bounded_and_fail_closed(self):
        cookie_pattern = re.search(
            r'"~\^\(\?<cookie_web_public_server_id>([^\n]+?)\)\$"', self.source,
        ).group(1)
        path_pattern = re.search(
            r'"~\^/game/\(\?<path_public_server_id>([^\n]+?)\)\(\?:/\|\$\)"',
            self.source,
        ).group(1)
        self.assertEqual(cookie_pattern, "[a-z0-9]{1,48}")
        self.assertEqual(path_pattern, cookie_pattern)
        valid_cookie = lambda value: value not in self.cookie_routes and re.fullmatch(cookie_pattern, value)
        for value in ("pep", "qa160", "s1", "a" * 48):
            self.assertTrue(valid_cookie(value), value)
        for value in ("", "PEP", "pep-1", "pep_1", "pep/1", "../pep", "한글", "a" * 49, *sorted(APP_PAGE_ROOTS), "all"):
            self.assertFalse(valid_cookie(value), value)
        for sibling in ("territory2", "corps2", "records2", "create2"):
            self.assertTrue(valid_cookie(sibling), "route matching must end at / or end of path")


if __name__ == "__main__":
    unittest.main(verbosity=2)
