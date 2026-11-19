# Hex-Clash

自用 OpenClash / Mihomo 分流规则集与自动化运维套件。针对异地双软路由高可用架构设计，兼顾轻量化、毫秒级命中与防污染策略。

---

## 📁 规则矩阵架构

* **`Ai/`** —— 主流 AI 大模型与代码生成工具分流规则
  * `Claude` / `OpenAI` / `Copilot` / `CurSor` / `Gemini` / `Grok` / `Perplexity` / `MetaAi` / `OpenRouter` / `Kiro`
* **`Community/`** —— 开发者与极客社区专项
  * `LinuxDo` / `NodeSeek` / `V2EX`
* **`Game/`** —— 游戏加速与游戏平台直连
  * `HonorofKings` 等
* **`Media/`** —— 流媒体与网络电视
  * `TVBox`（纯净收敛规则） / `Crunchyroll` 等
* **`Check.list`** —— 节点网络质量、IP 纯净度与 DNS/WebRTC 泄露检测专用规则集（包含 Ookla 测速、Scamalytics IP 欺诈分、IPQualityScore 风控探针，严格排毒杜绝泛解析抢占）
* **`GooglePlay.list`** —— 应用商店下载链路加速规则集

---

## 🛡️ 软路由自嵌内联规则加固 (Inline Rules)

在异地双软路由主配置 `/etc/openclash/HexClash.yaml` 的顶层 `rules:` 中，内嵌专属防风控与协议穿透规则：

* **Cloudflare Turnstile / Challenges 人机验证专线**：
  * 阻断 `challenges.cloudflare.com` 与 `challenges.cloudflare.net` 的 IPv6 泄露，强制 Clean IPv4；
  * 聚合调度 `turnstile.cloudflare.com`、`challenges.cloudflare.net`、`static.cloudflareinsights.com`、`cf-assets.hcaptcha.com` 走高洁净度节点，杜绝验证死循环。
* **Stripe 国际支付与 3DS 防风控专线**：
  * 统筹 `stripe.com`、`stripe.network`、`stripecdn.com`、`stripe-payments.com` 及 Visa/Mastercard 3D Secure 验证网关 `cardinalcommerce.com`，防范换 IP 导致的拒付与风控。
* **Apple APNs 毫秒级推送保活**：
  * 放行 DST-PORT `5223` 并内嵌直连 `push.apple.com`、`courier.push.apple.com`、`gateway.push.apple.com`，保障锁屏消息低延迟秒触达且避免电量消耗。

---

## 🛠️ 自动化工具链

### 1. 规则洗血与差集补漏引擎 (`tools/wash_rules.py`)

用于与业界顶尖上游仓库（**v2fly DLC**、**blackmatrix7**、**Repcz**）进行自动化差集比对与定期“洗血”注入：

* **防污染拦截**：内置高危泛化主域名黑名单（如 `auth0.com`、`launchdarkly.com`、`segment.io`、`algolia.net` 等通用 SaaS/CDN/Auth 主域名），严防流量劫持与策略组抢占。
* **智能泛域名覆盖判断**：自动识别已有 `DOMAIN-SUFFIX` 或 `DOMAIN-KEYWORD` 对子域名的覆盖关系，剔除冗余垃圾规则。
* **一键应用与本地编译**：支持一键将候选域名规范化补入 `.list`、重新计算统计 Header，并调用本地 `mihomo` 编译器生成二进制 `.mrs`。

#### 使用命令

```bash
# 仅比对分析，输出候选新域名与拦截详情（默认分析全部预设分类）
python tools/wash_rules.py claude
python tools/wash_rules.py openai
python tools/wash_rules.py copilot

# 一键清洗补入并本地自动编译 .mrs
python tools/wash_rules.py claude --apply
python tools/wash_rules.py --apply  # 对全部预设分类执行
```

### 2. GitHub Actions 自动编译工作流 (`.github/workflows/build-mrs.yml`)

* 任何 `.list` 规则文件推送至 `main` 分支时，自动拉取最新 Mihomo Core；
* 规范化处理规则并批量编译生成同名同目录的 `.mrs` 二进制规则集；
* 自动提交并发布最新编译资产。

---

## 🔄 双软路由订阅配置示例 (Rule Provider)

```yaml
rule-providers:
  Claude / Domain:
    type: http
    interval: 86400
    behavior: domain
    format: mrs
    url: https://gh-proxy.org/raw.githubusercontent.com/HexTTX/Hex-Clash/main/Ai/Claude.mrs
    path: "./rule_provider/Claude / Domain"

  ChatGPT / Domain:
    type: http
    interval: 86400
    behavior: domain
    format: mrs
    url: https://gh-proxy.org/raw.githubusercontent.com/HexTTX/Hex-Clash/main/Ai/OpenAI.mrs
    path: "./rule_provider/ChatGPT / Domain"
```
