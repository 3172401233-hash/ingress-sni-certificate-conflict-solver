# ingress-sni-certificate-conflict-solver
求解 Ingress SNI、证书 SAN 和默认证书冲突

## 说明

本工具**只分析静态配置**:不连接真实集群、不发起 TLS 握手、不读取
运行态 Secret 内容。给定一份 JSON 配置(Host、SNI、通配规则、证书 SAN、
Secret 版本、默认证书、路径、后端、TLS 选项、控制器优先级),它推导
两阶段选择结果并输出冲突证明与建议修复顺序。

## 两阶段模型

- **握手阶段(证书选择)**:按 SNI 匹配 TLS 规则(精确 > 通配,通配仅
  覆盖一层标签);未命中任何规则时由默认证书吞掉;同一 SAN 由多个
  Secret 提供时按控制器策略(默认 `highest_version`)选择。
- **请求阶段(路由选择)**:按 Host 匹配路由(精确 > 通配),再按路径
  最长前缀 / Exact 匹配,平局按控制器优先级与声明顺序裁决。

## 可区分的冲突

- `cert_expired`:证书已过期
- `cross_namespace_secret`:Secret 跨命名空间引用且未开启允许
- `san_mismatch`:证书 SAN 不覆盖 SNI
- `same_san_multiple_secrets`:同 SAN 多 Secret 版本竞争
- `sni_host_divergence`:握手成功但 Host 不被证书覆盖、指向不同后端
- `default_cert_swallow`:未匹配 SNI 被默认证书吞掉
- `exact_rule_overlap`:多条精确 TLS 规则同时命中
- `path_overlap`:同 Host 下路径重叠指向不同后端

## 使用

```bash
python3 ingress_analyzer.py config.json
```

输入示例见测试用例;输出包含 `certificate`(证书选择)、`route`
(路由选择)、`conflicts`(冲突证明)与 `fix_order`(建议修复顺序,
过期证书优先,路径重叠最后)。

## 测试

```bash
python -m unittest
```

覆盖:SNI 与 Host 不同、通配层级、默认证书、过期证书、同 SAN 多
Secret、路径重叠、跨命名空间引用与修复顺序排序。
