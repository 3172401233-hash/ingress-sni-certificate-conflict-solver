"""Ingress 两阶段(握手 / 请求)静态分析器。

只分析静态配置:给定 Host、SNI、通配规则、证书 SAN、Secret 版本、
默认证书、路径、后端、TLS 选项与控制器优先级,推导最终证书与路由,
并输出冲突证明与建议修复顺序。不连接真实集群,不发起 TLS 握手。

兼容 Python 3.8.2。
"""

import json
from datetime import datetime


# ---------------------------------------------------------------------------
# 基础匹配语义
# ---------------------------------------------------------------------------

def is_wildcard(host):
    return host.startswith("*.")


def wildcard_match(pattern, host):
    """通配仅覆盖一层标签:*.example.com 匹配 a.example.com,
    不匹配 example.com 或 a.b.example.com。"""
    if not is_wildcard(pattern):
        return pattern == host
    suffix = pattern[1:]  # ".example.com"
    if not host.endswith(suffix):
        return False
    head = host[: -len(suffix)]
    return head != "" and "." not in head


def san_covers(san, host):
    """证书 SAN 覆盖判断,与通配层级语义一致。"""
    return wildcard_match(san, host)


def host_match_score(rule_host, host):
    """返回 (是否匹配, 精确度分数)。精确 > 通配,通配越长越精确。"""
    if is_wildcard(rule_host):
        return (wildcard_match(rule_host, host), len(rule_host))
    return (rule_host == host, len(rule_host) + 1000)


def parse_time(value):
    if value is None:
        return None
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# 配置模型
# ---------------------------------------------------------------------------

class Secret(object):
    def __init__(self, name, namespace, version, sans, not_after=None):
        self.name = name
        self.namespace = namespace
        self.version = version
        self.sans = list(sans)
        self.not_after = parse_time(not_after)

    @property
    def ref(self):
        return "%s/%s" % (self.namespace, self.name)

    def covers(self, host):
        return any(san_covers(san, host) for san in self.sans)

    def expired(self, now):
        return self.not_after is not None and self.not_after <= now


class TLSRule(object):
    def __init__(self, hosts, secret_ref, options=None):
        self.hosts = list(hosts)
        self.secret_ref = secret_ref  # "namespace/name"
        self.options = options or {}


class Route(object):
    def __init__(self, host, path, backend, path_type="Prefix", priority=0, index=0):
        self.host = host
        self.path = path
        self.backend = backend
        self.path_type = path_type
        self.priority = priority
        self.index = index

    def path_matches(self, req_path):
        if self.path_type == "Exact":
            return req_path == self.path
        if self.path == "/":
            return True
        base = self.path if self.path.endswith("/") else self.path + "/"
        return req_path == self.path or req_path.startswith(base)


class Config(object):
    def __init__(self, data):
        req = data.get("request", {})
        self.req_host = req.get("host", "")
        self.req_sni = req.get("sni", "")
        self.req_path = req.get("path", "/")

        self.secrets = {}
        for s in data.get("secrets", []):
            sec = Secret(
                name=s["name"],
                namespace=s["namespace"],
                version=s.get("version", 1),
                sans=s.get("sans", []),
                not_after=s.get("not_after"),
            )
            self.secrets[sec.ref] = sec

        self.tls_rules = [
            TLSRule(t.get("hosts", []), t.get("secret", ""), t.get("options"))
            for t in data.get("tls_rules", [])
        ]

        self.routes = [
            Route(
                host=r.get("host", ""),
                path=r.get("path", "/"),
                backend=r.get("backend", ""),
                path_type=r.get("path_type", "Prefix"),
                priority=r.get("priority", 0),
                index=i,
            )
            for i, r in enumerate(data.get("routes", []))
        ]

        self.default_certificate = data.get("default_certificate")
        ctrl = data.get("controller", {})
        self.ingress_namespace = ctrl.get("ingress_namespace", "ingress-nginx")
        self.allow_cross_namespace = ctrl.get("allow_cross_namespace", False)
        self.secret_selection = ctrl.get("secret_selection", "highest_version")
        self.now = parse_time(data.get("now")) or datetime.utcnow()


# ---------------------------------------------------------------------------
# 冲突与修复建议
# ---------------------------------------------------------------------------

# 修复顺序:数字越小越应先修。
FIX_ORDER = {
    "cert_expired": 1,
    "cross_namespace_secret": 2,
    "san_mismatch": 3,
    "same_san_multiple_secrets": 4,
    "sni_host_divergence": 5,
    "default_cert_swallow": 6,
    "exact_rule_overlap": 7,
    "path_overlap": 8,
}

FIX_HINT = {
    "cert_expired": "先续期/轮换过期证书,恢复握手可用性",
    "cross_namespace_secret": "把 Secret 复制到 Ingress 命名空间或开启跨命名空间引用",
    "san_mismatch": "让证书 SAN 覆盖 SNI,或把 SNI 改到 SAN 覆盖的域名",
    "same_san_multiple_secrets": "合并同 SAN 的多个 Secret,消除版本竞争",
    "sni_host_divergence": "统一 SNI 与 Host,或让证书 SAN 同时覆盖两者",
    "default_cert_swallow": "为该 SNI 补 TLS 规则,避免被默认证书吞掉",
    "exact_rule_overlap": "合并同时命中的多条精确 TLS 规则",
    "path_overlap": "明确路径优先级或拆分重叠路径的后端",
}


class Conflict(object):
    def __init__(self, kind, proof):
        self.kind = kind
        self.proof = proof

    def as_dict(self):
        return {
            "kind": self.kind,
            "fix_order": FIX_ORDER[self.kind],
            "proof": self.proof,
            "suggestion": FIX_HINT[self.kind],
        }


# ---------------------------------------------------------------------------
# 阶段一:握手(证书选择)
# ---------------------------------------------------------------------------

def select_certificate(cfg, conflicts):
    sni = cfg.req_sni
    matched = []  # (score, rule, matched_host)
    for rule in cfg.tls_rules:
        best = None
        for h in rule.hosts:
            ok, score = host_match_score(h, sni)
            if ok and (best is None or score > best[0]):
                best = (score, h)
        if best:
            matched.append((best[0], rule, best[1]))

    chosen = None
    source = None
    if matched:
        matched.sort(key=lambda m: -m[0])
        top_score = matched[0][0]
        top = [m for m in matched if m[0] == top_score]
        if len(top) > 1:
            conflicts.append(Conflict(
                "exact_rule_overlap",
                "SNI %r 同时命中 %d 条同级 TLS 规则: %s"
                % (sni, len(top), [m[1].secret_ref for m in top]),
            ))
        candidates = []
        for _, rule, _ in top:
            sec = cfg.secrets.get(rule.secret_ref)
            if sec is not None:
                candidates.append(sec)
        if candidates:
            same_san = {}
            for sec in candidates:
                key = tuple(sorted(sec.sans))
                same_san.setdefault(key, []).append(sec)
            for key, group in same_san.items():
                if len(group) > 1:
                    conflicts.append(Conflict(
                        "same_san_multiple_secrets",
                        "SAN %s 同时由多个 Secret 提供: %s"
                        % (list(key), ["%s(v%d)" % (g.ref, g.version) for g in group]),
                    ))
            if cfg.secret_selection == "highest_version":
                chosen = max(candidates, key=lambda s: s.version)
            else:
                chosen = candidates[0]
            source = "tls_rule"
        else:
            source = "missing_secret"

    if chosen is None and source != "missing_secret":
        default = cfg.secrets.get(cfg.default_certificate or "")
        if default is not None:
            chosen = default
            source = "default_certificate"
            conflicts.append(Conflict(
                "default_cert_swallow",
                "SNI %r 未命中任何 TLS 规则,被默认证书 %s 吞掉"
                % (sni, default.ref),
            ))

    if chosen is not None:
        if chosen.expired(cfg.now):
            conflicts.append(Conflict(
                "cert_expired",
                "证书 %s 已于 %s 过期"
                % (chosen.ref, chosen.not_after.strftime("%Y-%m-%dT%H:%M:%SZ")),
            ))
        if chosen.namespace != cfg.ingress_namespace and not cfg.allow_cross_namespace:
            conflicts.append(Conflict(
                "cross_namespace_secret",
                "Secret %s 跨命名空间引用(控制器命名空间 %s,未开启允许)"
                % (chosen.ref, cfg.ingress_namespace),
            ))
        if not chosen.covers(sni):
            conflicts.append(Conflict(
                "san_mismatch",
                "证书 %s 的 SAN %s 不覆盖 SNI %r"
                % (chosen.ref, chosen.sans, sni),
            ))

    return {
        "sni": sni,
        "secret": chosen.ref if chosen else None,
        "secret_version": chosen.version if chosen else None,
        "sans": chosen.sans if chosen else [],
        "source": source if chosen else (source or "no_certificate"),
        "handshake_ok": chosen is not None and chosen.covers(sni)
        and not chosen.expired(cfg.now),
    }


# ---------------------------------------------------------------------------
# 阶段二:请求(路由选择)
# ---------------------------------------------------------------------------

def select_route(cfg, conflicts):
    host = cfg.req_host
    path = cfg.req_path

    host_matched = []
    for route in cfg.routes:
        ok, score = host_match_score(route.host, host)
        if ok:
            host_matched.append((score, route))
    if not host_matched:
        return {"host": host, "path": path, "backend": None,
                "matched_route": None, "reason": "no_host_match"}

    best_host_score = max(s for s, _ in host_matched)
    candidates = [r for s, r in host_matched if s == best_host_score]

    path_matched = [r for r in candidates if r.path_matches(path)]
    if not path_matched:
        return {"host": host, "path": path, "backend": None,
                "matched_route": None, "reason": "no_path_match"}

    path_matched.sort(key=lambda r: (-len(r.path), -r.priority, r.index))
    winner = path_matched[0]

    overlaps = [r for r in path_matched[1:]
                if r.backend != winner.backend]
    if overlaps:
        conflicts.append(Conflict(
            "path_overlap",
            "路径 %r 在主机 %r 下同时命中多条路由: 选中 %s(%s), 备选 %s"
            % (path, host, winner.path, winner.backend,
               ["%s(%s)" % (r.path, r.backend) for r in overlaps]),
        ))

    return {
        "host": host,
        "path": path,
        "backend": winner.backend,
        "matched_route": {"host": winner.host, "path": winner.path,
                          "path_type": winner.path_type},
        "reason": "matched",
    }


# ---------------------------------------------------------------------------
# 跨阶段:握手成功但 Host 不匹配
# ---------------------------------------------------------------------------

def check_divergence(cfg, cert_result, route_result, conflicts):
    sni = cfg.req_sni
    host = cfg.req_host
    if not cert_result["handshake_ok"]:
        return
    if sni == host:
        return
    cert_ref = cert_result["secret"]
    sec = cfg.secrets.get(cert_ref)
    cert_covers_host = sec is not None and sec.covers(host)
    if not cert_covers_host:
        conflicts.append(Conflict(
            "sni_host_divergence",
            "握手按 SNI %r 选证书 %s,但请求 Host %r 不被该证书 SAN 覆盖,"
            "且 Host 路由指向后端 %s(与 SNI 规则后端可能不同)"
            % (sni, cert_ref, host, route_result["backend"]),
        ))


# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------

def analyze(data):
    cfg = Config(data)
    conflicts = []
    cert = select_certificate(cfg, conflicts)
    route = select_route(cfg, conflicts)
    check_divergence(cfg, cert, route, conflicts)

    ordered = sorted(conflicts, key=lambda c: FIX_ORDER[c.kind])
    return {
        "certificate": cert,
        "route": route,
        "conflicts": [c.as_dict() for c in ordered],
        "fix_order": [
            {"order": FIX_ORDER[c.kind], "kind": c.kind,
             "suggestion": FIX_HINT[c.kind]}
            for c in ordered
        ],
    }


def main(argv=None):
    import sys
    argv = argv if argv is not None else sys.argv[1:]
    if not argv:
        sys.stderr.write("usage: python ingress_analyzer.py <config.json>\n")
        return 2
    with open(argv[0], "r") as fh:
        data = json.load(fh)
    json.dump(analyze(data), sys.stdout, ensure_ascii=False, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
