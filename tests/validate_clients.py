#!/usr/bin/env python3
"""校验两端配置的关键安全约束和本地引用。"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parents[1]
SHADOWROCKET = ROOT / "clients" / "Shadowrocket.conf"
CLASH = ROOT / "clients" / "clash-verge.js"
ROUTING_CASES = ROOT / "tests" / "expected-routing.json"
RAW_PREFIX = "https://raw.githubusercontent.com/kerwinruby/Shadowrocket-Rules/refs/heads/main/"
SENSITIVE = re.compile(r"(?i)(token|password|passwd|secret|api[_-]?key)\s*[=:]\s*[^\s,]+")


def fail(errors: list[str], message: str) -> None:
    errors.append(message)


def require_order(errors: list[str], label: str, text: str, markers: list[str]) -> None:
    positions = [text.find(marker) for marker in markers]
    missing = [marker for marker, position in zip(markers, positions) if position < 0]
    if missing:
        fail(errors, f"{label} 缺少规则顺序标记: {', '.join(missing)}")
    elif positions != sorted(positions):
        fail(errors, f"{label} 规则优先级与统一契约不一致")


def parse_shadowrocket_groups(text: str) -> dict[str, list[str]]:
    groups: dict[str, list[str]] = {}
    in_section = False
    for line in text.splitlines():
        if line == "[Proxy Group]":
            in_section = True
            continue
        if in_section and line.startswith("["):
            break
        if in_section and " = " in line:
            name, value = line.split(" = ", 1)
            groups[name] = [item.strip() for item in value.split(",")]
    return groups


def validate_shadowrocket(errors: list[str]) -> None:
    text = SHADOWROCKET.read_text(encoding="utf-8")
    lines = text.splitlines()
    groups = parse_shadowrocket_groups(text)
    if "ipv6 = false" not in text or "prefer-ipv6 = false" not in text:
        fail(errors, "Shadowrocket 未显式关闭 IPv6")

    for key in ("dns-server =", "fallback-dns-server ="):
        line = next((item for item in lines if item.startswith(key)), "")
        values = [value.strip() for value in line.split("=", 1)[-1].split(",")]
        if not values or any(urlparse(value).scheme != "https" for value in values):
            fail(errors, f"Shadowrocket {key.rstrip()} 必须全部使用 HTTPS DoH")

    if "DOMAIN-KEYWORD,stun" in text or "DOMAIN-KEYWORD,turn" in text:
        fail(errors, "Shadowrocket 禁止使用过宽的 STUN/TURN 关键词规则")
    for port in (3478, 5349, *range(19302, 19310)):
        rule = f"AND,((PROTOCOL,UDP),(DEST-PORT,{port})),REJECT"
        if rule not in text:
            fail(errors, f"Shadowrocket 缺少 WebRTC UDP 拒绝规则: {port}")
    if "BlockHttpDNS/BlockHttpDNS.list,REJECT" not in text:
        fail(errors, "Shadowrocket HTTPDNS 防泄露规则必须直接 REJECT")
    if "🧱 DNS 防泄露 =" in text:
        fail(errors, "Shadowrocket 不应将 DNS 防泄露暴露为可切换代理组")

    for line in lines:
        if not line.startswith("RULE-SET,") or RAW_PREFIX not in line:
            continue
        url = line.split(",", 2)[1]
        relative = url.removeprefix(RAW_PREFIX)
        if relative.startswith("rules/") and not (ROOT / relative).is_file():
            fail(errors, f"Shadowrocket 引用了不存在的本地规则: {relative}")

    expected_url = RAW_PREFIX + "clients/Shadowrocket.conf"
    if f"update-url = {expected_url}" not in text:
        fail(errors, "Shadowrocket update-url 与发布路径不一致")

    expected_defaults = {
        "🚀 节点选择": "PROXY",
        "🔗 全局直连": "DIRECT",
        "❌ 全局拦截": "REJECT",
        "🛑 广告拦截": "❌ 全局拦截",
        "💸 OpenAI": "🇺🇸 美国节点",
        "💵 Claude": "🇺🇸 美国节点",
        "🧠 XAI": "🇺🇸 美国节点",
        "🔎 Perplexity": "🇺🇸 美国节点",
        "📹 油管视频": "🚀 节点选择",
        "🔍 谷歌服务": "🇯🇵 日本节点",
        "Ⓜ️ 微软服务": "🚀 节点选择",
        "🍏 苹果服务": "🔗 全局直连",
        "🍎 苹果推送": "🚀 节点选择",
        "📲 电报消息": "🚀 节点选择",
        "🐱 代码托管": "🚀 节点选择",
        "📈 券商服务": "🇭🇰 香港节点",
        "🏠 私有网络": "🔗 全局直连",
        "🔒 国内服务": "🔗 全局直连",
        "🌍 非中国": "PROXY",
        "🐟 漏网之鱼": "PROXY",
    }
    for name, expected in expected_defaults.items():
        values = groups.get(name, [])
        actual = values[1] if len(values) > 1 and values[0] == "select" else None
        if actual != expected:
            fail(errors, f"Shadowrocket {name} 默认策略应为 {expected}，实际为 {actual}")

    require_order(errors, "Shadowrocket", text, [
        "rules/custom-direct.list",
        "rules/custom-proxy.list",
        "rules/custom-google.list",
        "rules/custom-code.list",
        "/Lan/Lan.list",
        "DOMAIN,shortconn.im.qcloud.com",
        "IP-CIDR,208.54.0.0/16",
        "/BlockHttpDNS/BlockHttpDNS.list",
        "/Advertising/Advertising.list",
        "rules/webrtc.list",
        "/YouTube/YouTube.list",
        "rules/openai.list",
        "rules/anthropic.list",
        "rules/xai.list",
        "rules/perplexity.list",
        "rules/google-gemini.list",
        "rules/google.list",
        "/BiliBili/BiliBili.list",
        "/Telegram/Telegram.list",
        "/GitHub/GitHub.list",
        "/GitLab/GitLab.list",
        "/Atlassian/Atlassian.list",
        "/Microsoft/Microsoft.list",
        "rules/broker.list",
        "rules/apple-push.list",
        "rules/apple.list",
        "/China/China.list",
        "/Global/Global.list",
        "GEOIP,CN",
        "FINAL,"
    ])


def validate_clash(errors: list[str]) -> None:
    text = CLASH.read_text(encoding="utf-8")
    if "config.ipv6 = false" not in text or "ipv6: false" not in text:
        fail(errors, "Clash 未同时关闭全局和 DNS IPv6")
    if '"enhanced-mode": "fake-ip"' not in text:
        fail(errors, "Clash 未启用 fake-ip")
    if '...(config["proxy-providers"] || {})' not in text or '...additionalProxyProviders' not in text:
        fail(errors, "Clash 未保留并合并多个代理订阅")
    if '"include-all": !["reject", "block-service"].includes(kind)' not in text:
        fail(errors, "Clash 自动策略组未纳入所有订阅节点")
    shadowrocket_text = SHADOWROCKET.read_text(encoding="utf-8")
    shadowrocket_groups = parse_shadowrocket_groups(shadowrocket_text)
    canonical_groups = (
        "🚀 节点选择", "🔗 全局直连", "❌ 全局拦截",
        "🇭🇰 香港节点", "🇹🇼 台湾节点", "🇯🇵 日本节点", "🇺🇸 美国节点", "🌐 其他节点",
        "🛑 广告拦截", "💸 OpenAI", "💵 Claude", "🧠 XAI", "🔎 Perplexity",
        "📹 油管视频", "🔍 谷歌服务", "Ⓜ️ 微软服务", "🍏 苹果服务",
        "🍎 苹果推送", "📲 电报消息", "🐱 代码托管", "📈 券商服务",
        "🏠 私有网络", "🔒 国内服务", "🌍 非中国", "🐟 漏网之鱼"
    )
    for group in canonical_groups:
        if group not in text or group not in shadowrocket_groups:
            fail(errors, f"两端缺少基础策略组: {group}")
    for obsolete in ("🔰 模式选择", "📢 谷歌服务", "🍎 苹果服务"):
        if obsolete in text:
            fail(errors, f"Clash 仍包含旧策略组名称: {obsolete}")
    for port in ("3478", "5349", "19302-19309"):
        if f"(DST-PORT,{port})" not in text:
            fail(errors, f"Clash 缺少 WebRTC UDP 拒绝规则: {port}")
    if '"RULE-SET,blockHttpDns,REJECT"' not in text:
        fail(errors, "Clash HTTPDNS 防泄露规则必须直接 REJECT")
    if '{ name: "🧱 DNS 防泄露"' in text:
        fail(errors, "Clash 不应将 DNS 防泄露暴露为可切换代理组")
    require_order(errors, "Clash", text, [
        '"RULE-SET,customDirect,',
        '"RULE-SET,customProxy,',
        '"RULE-SET,customGoogle,',
        '"RULE-SET,customCode,',
        '"RULE-SET,lan,',
        '"DOMAIN,shortconn.im.qcloud.com,',
        '"IP-CIDR,208.54.0.0/16,',
        '"RULE-SET,blockHttpDns,',
        '"RULE-SET,advertising,',
        '"RULE-SET,webrtc,',
        '"RULE-SET,youtube,',
        '"RULE-SET,openai,',
        '"RULE-SET,anthropic,',
        '"RULE-SET,xai,',
        '"RULE-SET,perplexity,',
        '"RULE-SET,googleGemini,',
        '"RULE-SET,google,',
        '"RULE-SET,bilibili,',
        '"RULE-SET,telegram,',
        '"RULE-SET,github,',
        '"RULE-SET,gitlab,',
        '"RULE-SET,atlassian,',
        '"RULE-SET,microsoft,',
        '"RULE-SET,broker,',
        '"RULE-SET,applePush,',
        '"RULE-SET,apple,',
        '"RULE-SET,china,',
        '"RULE-SET,global,',
        '"GEOIP,CN,🔗 全局直连,no-resolve"',
        '"MATCH,🐟 漏网之鱼"'
    ])
    if SENSITIVE.search(text):
        fail(errors, "Clash 脚本可能包含敏感凭据")


def main() -> int:
    errors: list[str] = []
    validate_shadowrocket(errors)
    validate_clash(errors)
    cases = json.loads(ROUTING_CASES.read_text(encoding="utf-8"))
    if len(cases) < 20:
        fail(errors, "路由验收样例少于 20 条")
    if errors:
        print("客户端配置校验失败:")
        print("\n".join(errors))
        return 1
    print(f"客户端配置校验通过: {len(cases)} 条路由样例")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
