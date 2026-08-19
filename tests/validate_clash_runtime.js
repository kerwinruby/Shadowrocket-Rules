#!/usr/bin/env node

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const root = path.resolve(__dirname, "..");
const script = fs.readFileSync(path.join(root, "clients", "clash-verge.js"), "utf8");
const context = vm.createContext({ console });
vm.runInContext(`${script}\n;globalThis.mainForTest = main;`, context);

const transportNames = [
  "⚙️ 节点选择",
  "🕊️ 落地节点",
  "♻️ 延迟选优",
  "🚑 故障转移",
  "⚖️ 负载均衡(散列)",
  "☁️ 负载均衡(轮询)"
];
const originalGroups = transportNames.map((name) => ({
  name,
  type: "select",
  proxies: ["测试节点"]
}));
const staleModeGroup = {
  name: "🚀 节点选择",
  type: "select",
  proxies: ["旧目标"]
};
const config = {
  proxies: [{ name: "测试节点", type: "ss" }],
  "proxy-groups": [...originalGroups, staleModeGroup],
  rules: ["DOMAIN,example.com,DIRECT", "GEOIP,CN,DIRECT", "MATCH,DIRECT"]
};

const result = context.mainForTest(config);
const groups = new Map(result["proxy-groups"].map((group) => [group.name, group]));
const direct = groups.get("🔗 全局直连");
const reject = groups.get("❌ 全局拦截");
const canonicalDefaults = new Map([
  ["💸 OpenAI", "🇺🇸 美国节点"],
  ["💵 Claude", "🇺🇸 美国节点"],
  ["🧠 XAI", "🇺🇸 美国节点"],
  ["🔎 Perplexity", "🇺🇸 美国节点"],
  ["🔍 谷歌服务", "🇯🇵 日本节点"],
  ["📈 券商服务", "🇭🇰 香港节点"],
  ["🍏 苹果服务", "🔗 全局直连"],
  ["🏠 私有网络", "🔗 全局直连"],
  ["🔒 国内服务", "🔗 全局直连"],
  ["🛑 广告拦截", "❌ 全局拦截"]
]);

assert.equal(result.ipv6, false, "Clash 全局 IPv6 出口必须关闭");
assert.equal(result.dns.enable, true, "Clash DNS 必须启用");
assert.equal(result.dns.ipv6, false, "Clash DNS 不应返回 IPv6 地址");
assert.equal(result.dns["enhanced-mode"], "fake-ip", "Clash DNS 必须使用 fake-ip 模式");
assert.equal(result.dns["respect-rules"], true, "DNS 查询必须遵循分流规则");
assert.equal(result.dns["use-system-hosts"], false, "DNS 不应回退系统 hosts");
assert.equal(
  result.dns["direct-nameserver-follow-policy"],
  false,
  "直连 DNS 不应绕过指定的 DoH"
);

const dohKeys = ["nameserver", "proxy-server-nameserver", "direct-nameserver"];
for (const key of dohKeys) {
  assert.ok(result.dns[key].length > 0, `DNS 配置 ${key} 不得为空`);
  for (const server of result.dns[key]) {
    assert.ok(server.startsWith("https://"), `DNS 配置 ${key} 必须全部使用 DoH: ${server}`);
  }
}
for (const servers of Object.values(result.dns["nameserver-policy"])) {
  for (const server of servers) {
    assert.ok(server.startsWith("https://"), `DNS 分流策略必须全部使用 DoH: ${server}`);
  }
}

assert.ok(direct, "未自动创建全局直连组");
assert.ok(reject, "未自动创建全局拦截组");
assert.ok(!groups.has("🧱 DNS 防泄露"), "DNS 防泄露不应是可切换代理组");
assert.equal(direct.proxies[0], "DIRECT", "全局直连的默认策略必须为 DIRECT");
assert.equal(reject.proxies[0], "REJECT", "全局拦截的默认策略必须为 REJECT");
assert.equal(groups.get("⚙️ 节点选择"), originalGroups[0], "不应覆盖订阅已有策略组");
assert.notEqual(groups.get("🚀 节点选择"), staleModeGroup, "必须按统一契约重建同名策略组");
for (const [name, expected] of canonicalDefaults) {
  assert.equal(groups.get(name)?.proxies[0], expected, `${name} 的默认策略必须为 ${expected}`);
}
for (const name of ["🇭🇰 香港节点", "🇹🇼 台湾节点", "🇯🇵 日本节点", "🇺🇸 美国节点", "🌐 其他节点"]) {
  assert.equal(groups.get(name)?.type, "url-test", `${name} 必须是自动测速组`);
}
assert.ok(groups.get("🌐 其他节点")["exclude-filter"], "其他节点必须排除已知地区关键词");
for (const obsolete of ["🔰 模式选择", "📢 谷歌服务", "🍎 苹果服务"]) {
  assert.ok(!groups.has(obsolete), `不得生成旧策略组名称 ${obsolete}`);
}

const builtins = new Set(["DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE"]);
const proxyNames = new Set(result.proxies.map((proxy) => proxy.name));
for (const group of groups.values()) {
  for (const target of group.proxies || []) {
    assert.ok(
      builtins.has(target) || proxyNames.has(target) || groups.has(target),
      `策略组 ${group.name} 引用了不存在的目标 ${target}`
    );
  }
}

// 只检查策略组之间的依赖；节点和内置动作是叶子节点。
const visiting = new Set();
const visited = new Set();
function visit(name) {
  if (visiting.has(name)) {
    assert.fail(`策略组存在循环引用: ${name}`);
  }
  if (visited.has(name)) {
    return;
  }
  visiting.add(name);
  for (const target of groups.get(name).proxies || []) {
    if (groups.has(target)) {
      visit(target);
    }
  }
  visiting.delete(name);
  visited.add(name);
}
for (const name of groups.keys()) {
  visit(name);
}

const ruleTargets = result.rules.map((rule) => {
  const parts = rule.split(",");
  return parts.at(-1) === "no-resolve" ? parts.at(-2) : parts.at(-1);
});
for (const target of ruleTargets) {
  assert.ok(builtins.has(target) || groups.has(target), `规则引用了不存在的策略 ${target}`);
}
assert.ok(result.rules.includes("DOMAIN,example.com,DIRECT"), "应保留订阅原有的非终结规则");
assert.ok(result.rules.includes("RULE-SET,blockHttpDns,REJECT"), "HTTPDNS 必须直接拒绝");
assert.ok(!result.rules.includes("MATCH,DIRECT"), "应移除订阅原有的终结规则");
assert.equal(result.rules.at(-1), "MATCH,🐟 漏网之鱼", "统一兜底规则必须位于末尾");

console.log(`Clash 运行时校验通过: ${groups.size} 个策略组，${result.rules.length} 条规则`);
