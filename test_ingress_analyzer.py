"""ingress_analyzer 的单元测试,Python 3.8.2 / unittest。"""

import unittest

from ingress_analyzer import analyze, wildcard_match


NOW = "2026-11-22T00:00:00Z"


def base_config():
    return {
        "now": NOW,
        "request": {"host": "api.example.com", "sni": "api.example.com",
                    "path": "/"},
        "controller": {"ingress_namespace": "ingress-nginx",
                       "allow_cross_namespace": False,
                       "secret_selection": "highest_version"},
        "secrets": [],
        "tls_rules": [],
        "routes": [],
        "default_certificate": None,
    }


def kinds(result):
    return [c["kind"] for c in result["conflicts"]]


class WildcardLevelTest(unittest.TestCase):
    def test_wildcard_levels(self):
        self.assertTrue(wildcard_match("*.example.com", "a.example.com"))
        self.assertFalse(wildcard_match("*.example.com", "example.com"))
        self.assertFalse(wildcard_match("*.example.com", "a.b.example.com"))
        self.assertTrue(wildcard_match("*.a.example.com", "b.a.example.com"))

    def test_wildcard_cert_covers_handshake(self):
        cfg = base_config()
        cfg["request"]["sni"] = "api.example.com"
        cfg["secrets"] = [{
            "name": "wild", "namespace": "ingress-nginx", "version": 1,
            "sans": ["*.example.com"], "not_after": "2027-01-01T00:00:00Z",
        }]
        cfg["tls_rules"] = [{"hosts": ["*.example.com"],
                             "secret": "ingress-nginx/wild"}]
        result = analyze(cfg)
        self.assertEqual(result["certificate"]["secret"], "ingress-nginx/wild")
        self.assertEqual(result["certificate"]["source"], "tls_rule")
        self.assertTrue(result["certificate"]["handshake_ok"])
        self.assertEqual(result["conflicts"], [])

    def test_wildcard_does_not_cover_deeper_level(self):
        cfg = base_config()
        cfg["request"]["sni"] = "a.b.example.com"
        cfg["secrets"] = [
            {"name": "wild", "namespace": "ingress-nginx", "version": 1,
             "sans": ["*.example.com"], "not_after": "2027-01-01T00:00:00Z"},
            {"name": "default", "namespace": "ingress-nginx", "version": 1,
             "sans": ["default.local"], "not_after": "2027-01-01T00:00:00Z"},
        ]
        cfg["tls_rules"] = [{"hosts": ["*.example.com"],
                             "secret": "ingress-nginx/wild"}]
        cfg["default_certificate"] = "ingress-nginx/default"
        result = analyze(cfg)
        self.assertEqual(result["certificate"]["source"], "default_certificate")
        self.assertIn("default_cert_swallow", kinds(result))


class SniHostDivergenceTest(unittest.TestCase):
    def test_handshake_ok_but_host_mismatch(self):
        cfg = base_config()
        cfg["request"] = {"host": "web.other.com", "sni": "api.example.com",
                          "path": "/"}
        cfg["secrets"] = [{
            "name": "api", "namespace": "ingress-nginx", "version": 1,
            "sans": ["api.example.com"], "not_after": "2027-01-01T00:00:00Z",
        }]
        cfg["tls_rules"] = [{"hosts": ["api.example.com"],
                             "secret": "ingress-nginx/api"}]
        cfg["routes"] = [
            {"host": "api.example.com", "path": "/", "backend": "api-svc:80"},
            {"host": "web.other.com", "path": "/", "backend": "web-svc:80"},
        ]
        result = analyze(cfg)
        self.assertTrue(result["certificate"]["handshake_ok"])
        self.assertEqual(result["route"]["backend"], "web-svc:80")
        self.assertIn("sni_host_divergence", kinds(result))
        proof = [c for c in result["conflicts"]
                 if c["kind"] == "sni_host_divergence"][0]["proof"]
        self.assertIn("api.example.com", proof)
        self.assertIn("web.other.com", proof)


class DefaultCertTest(unittest.TestCase):
    def test_default_cert_swallows_unmatched_sni(self):
        cfg = base_config()
        cfg["request"]["sni"] = "unknown.example.net"
        cfg["secrets"] = [{
            "name": "default", "namespace": "ingress-nginx", "version": 1,
            "sans": ["default.local"], "not_after": "2027-01-01T00:00:00Z",
        }]
        cfg["default_certificate"] = "ingress-nginx/default"
        result = analyze(cfg)
        cert = result["certificate"]
        self.assertEqual(cert["secret"], "ingress-nginx/default")
        self.assertEqual(cert["source"], "default_certificate")
        self.assertFalse(cert["handshake_ok"])
        self.assertIn("default_cert_swallow", kinds(result))
        self.assertIn("san_mismatch", kinds(result))


class ExpiredCertTest(unittest.TestCase):
    def test_expired_certificate(self):
        cfg = base_config()
        cfg["secrets"] = [{
            "name": "old", "namespace": "ingress-nginx", "version": 1,
            "sans": ["api.example.com"], "not_after": "2026-01-01T00:00:00Z",
        }]
        cfg["tls_rules"] = [{"hosts": ["api.example.com"],
                             "secret": "ingress-nginx/old"}]
        result = analyze(cfg)
        self.assertFalse(result["certificate"]["handshake_ok"])
        self.assertIn("cert_expired", kinds(result))
        expired = [c for c in result["conflicts"]
                   if c["kind"] == "cert_expired"][0]
        self.assertEqual(expired["fix_order"], 1)


class SameSanMultipleSecretsTest(unittest.TestCase):
    def test_same_san_version_competition(self):
        cfg = base_config()
        cfg["secrets"] = [
            {"name": "v1", "namespace": "ingress-nginx", "version": 1,
             "sans": ["api.example.com"], "not_after": "2027-01-01T00:00:00Z"},
            {"name": "v2", "namespace": "ingress-nginx", "version": 2,
             "sans": ["api.example.com"], "not_after": "2027-06-01T00:00:00Z"},
        ]
        cfg["tls_rules"] = [
            {"hosts": ["api.example.com"], "secret": "ingress-nginx/v1"},
            {"hosts": ["api.example.com"], "secret": "ingress-nginx/v2"},
        ]
        result = analyze(cfg)
        self.assertEqual(result["certificate"]["secret"], "ingress-nginx/v2")
        self.assertEqual(result["certificate"]["secret_version"], 2)
        self.assertIn("same_san_multiple_secrets", kinds(result))
        self.assertIn("exact_rule_overlap", kinds(result))


class PathOverlapTest(unittest.TestCase):
    def test_path_overlap_longest_wins(self):
        cfg = base_config()
        cfg["request"]["path"] = "/api/v1/users"
        cfg["secrets"] = [{
            "name": "api", "namespace": "ingress-nginx", "version": 1,
            "sans": ["api.example.com"], "not_after": "2027-01-01T00:00:00Z",
        }]
        cfg["tls_rules"] = [{"hosts": ["api.example.com"],
                             "secret": "ingress-nginx/api"}]
        cfg["routes"] = [
            {"host": "api.example.com", "path": "/api",
             "backend": "api-svc:80"},
            {"host": "api.example.com", "path": "/api/v1",
             "backend": "v1-svc:80"},
        ]
        result = analyze(cfg)
        self.assertEqual(result["route"]["backend"], "v1-svc:80")
        self.assertIn("path_overlap", kinds(result))

    def test_exact_path_beats_prefix(self):
        cfg = base_config()
        cfg["request"]["path"] = "/health"
        cfg["routes"] = [
            {"host": "api.example.com", "path": "/",
             "backend": "root-svc:80"},
            {"host": "api.example.com", "path": "/health",
             "path_type": "Exact", "backend": "health-svc:80"},
        ]
        result = analyze(cfg)
        self.assertEqual(result["route"]["backend"], "health-svc:80")


class CrossNamespaceTest(unittest.TestCase):
    def test_cross_namespace_secret_rejected(self):
        cfg = base_config()
        cfg["secrets"] = [{
            "name": "api", "namespace": "team-a", "version": 1,
            "sans": ["api.example.com"], "not_after": "2027-01-01T00:00:00Z",
        }]
        cfg["tls_rules"] = [{"hosts": ["api.example.com"],
                             "secret": "team-a/api"}]
        result = analyze(cfg)
        self.assertIn("cross_namespace_secret", kinds(result))

    def test_cross_namespace_allowed(self):
        cfg = base_config()
        cfg["controller"]["allow_cross_namespace"] = True
        cfg["secrets"] = [{
            "name": "api", "namespace": "team-a", "version": 1,
            "sans": ["api.example.com"], "not_after": "2027-01-01T00:00:00Z",
        }]
        cfg["tls_rules"] = [{"hosts": ["api.example.com"],
                             "secret": "team-a/api"}]
        result = analyze(cfg)
        self.assertNotIn("cross_namespace_secret", kinds(result))


class FixOrderTest(unittest.TestCase):
    def test_fix_order_sorted(self):
        cfg = base_config()
        cfg["request"] = {"host": "web.other.com", "sni": "api.example.com",
                          "path": "/x"}
        cfg["secrets"] = [{
            "name": "old", "namespace": "team-a", "version": 1,
            "sans": ["api.example.com"], "not_after": "2026-01-01T00:00:00Z",
        }]
        cfg["tls_rules"] = [{"hosts": ["api.example.com"],
                             "secret": "team-a/old"}]
        cfg["routes"] = [{"host": "web.other.com", "path": "/",
                          "backend": "web-svc:80"}]
        result = analyze(cfg)
        orders = [f["order"] for f in result["fix_order"]]
        self.assertEqual(orders, sorted(orders))
        self.assertEqual(result["fix_order"][0]["kind"], "cert_expired")


if __name__ == "__main__":
    unittest.main()
