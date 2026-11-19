#!/usr/bin/env python3
"""
wash_rules.py - 自建规则库洗血与补漏分析引擎
用于从 v2fly (DLC), blackmatrix7, Repcz 等业界顶尖上游仓库提取规则，
进行差集比对、泛域名智能覆盖检测、过宽污染过滤，并支持自动格式化补入自建库、重新计算头部元数据及本地编译 .mrs。
"""

import os
import re
import sys
import shutil
import tempfile
import subprocess
import urllib.request
import urllib.error
from datetime import datetime
from typing import Dict, List, Set, Tuple

# 高危或泛化主域名黑名单（严禁作为全量 DOMAIN-SUFFIX 加入特定规则，防止流量抢占与全局污染）
POISON_SUFFIX_BLACKLIST = {
    "cloudflare.com", "cloudflare.net", "cloudflareinsights.com",
    "azure.com", "azureedge.net", "azurefd.net", "windows.net",
    "amazonaws.com", "amazon.com",
    "akamai.net", "akamaized.net", "edgekey.net",
    "fastly.net",
    "google.com", "googleapis.com", "gstatic.com", "gvt1.com",
    "github.com", "githubusercontent.com",
    "apple.com", "icloud.com",
    "sentry.io", "datadoghq.com", "launchdarkly.com", "segment.io",
    "intercom.io", "intercomcdn.com", "stripe.com", "auth0.com",
    "mixpanel.com", "livekit.cloud", "statsig.com", "statsigapi.net",
    "algolia.net", "algolianet.com", "revenuecat.com",
}

# 上游血库源映射表
RULE_SOURCES = {
    "claude": {
        "local": "Ai/Claude.list",
        "v2fly": ["anthropic"],
        "blackmatrix7": ["Claude"],
        "repcz": ["Claude", "AI"],
    },
    "openai": {
        "local": "Ai/OpenAI.list",
        "v2fly": ["openai"],
        "blackmatrix7": ["OpenAI"],
        "repcz": ["AI"],
    },
    "copilot": {
        "local": "Ai/Copilot.list",
        "v2fly": ["github-copilot"],
        "blackmatrix7": ["Copilot"],
        "repcz": ["AI"],
    },
    "cursor": {
        "local": "Ai/CurSor.list",
        "blackmatrix7": ["Cursor"],
        "repcz": ["AI"],
    },
    "gemini": {
        "local": "Ai/Gemini.list",
        "v2fly": ["google-gemini"],
        "blackmatrix7": ["Gemini"],
        "repcz": ["AI"],
    },
    "grok": {
        "local": "Ai/Grok.list",
        "blackmatrix7": ["Grok"],
        "repcz": ["AI"],
    },
    "perplexity": {
        "local": "Ai/Perplexity.list",
        "blackmatrix7": ["Perplexity"],
        "repcz": ["AI"],
    },
    "linuxdo": {
        "local": "Community/LinuxDo.list",
        "blackmatrix7": ["LinuxDo"],
    },
    "check": {
        "local": "Check.list",
        "blackmatrix7": ["Check"],
    },
}

def fetch_url(url: str, timeout: int = 15) -> str:
    """拉取远程规则文本，带超时和常见 Headers"""
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "Mozilla/5.0 (compatible; HexClash-Washer/1.0)"}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return response.read().decode("utf-8", errors="ignore")
    except Exception:
        if "raw.githubusercontent.com" in url:
            proxy_url = url.replace("https://raw.githubusercontent.com", "https://gh-proxy.org/raw.githubusercontent.com")
            try:
                req_proxy = urllib.request.Request(
                    proxy_url,
                    headers={"User-Agent": "Mozilla/5.0 (compatible; HexClash-Washer/1.0)"}
                )
                with urllib.request.urlopen(req_proxy, timeout=timeout) as response:
                    return response.read().decode("utf-8", errors="ignore")
            except Exception:
                pass
        return ""

def parse_v2fly(content: str) -> List[Tuple[str, str]]:
    """解析 v2fly DLC 规则"""
    rules = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("@")[0].strip().split()
        if not parts:
            continue
        entry = parts[0]
        if entry.startswith("include:") or entry.startswith("regexp:"):
            continue
        if entry.startswith("full:"):
            domain = entry[5:].strip().lower()
            if domain:
                rules.append(("DOMAIN", domain))
        elif entry.startswith("keyword:"):
            kw = entry[8:].strip().lower()
            if kw:
                rules.append(("DOMAIN-KEYWORD", kw))
        else:
            domain = entry.lower()
            if domain:
                rules.append(("DOMAIN-SUFFIX", domain))
    return rules

def parse_clash_list(content: str) -> List[Tuple[str, str]]:
    """解析标准 Clash Classical .list 规则"""
    rules = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue
        parts = [p.strip() for p in line.split(",")]
        if len(parts) >= 2:
            rtype = parts[0].upper()
            val = parts[1].lower()
            if rtype in ("DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "IP-CIDR", "IP-CIDR6", "IP-ASN"):
                rules.append((rtype, val))
    return rules

class LocalRuleset:
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.exact_domains: Set[str] = set()
        self.suffix_domains: Set[str] = set()
        self.keywords: Set[str] = set()
        self.ips: Set[str] = set()
        self.raw_lines: List[str] = []
        self.load()

    def load(self):
        if not os.path.exists(self.filepath):
            return
        with open(self.filepath, "r", encoding="utf-8") as f:
            for line in f:
                self.raw_lines.append(line)
                sline = line.strip()
                if not sline or sline.startswith("#") or sline.startswith("//"):
                    continue
                parts = [p.strip() for p in sline.split(",")]
                if len(parts) >= 2:
                    rtype = parts[0].upper()
                    val = parts[1].lower()
                    if rtype == "DOMAIN":
                        self.exact_domains.add(val)
                    elif rtype == "DOMAIN-SUFFIX":
                        self.suffix_domains.add(val)
                    elif rtype == "DOMAIN-KEYWORD":
                        self.keywords.add(val)
                    elif rtype in ("IP-CIDR", "IP-CIDR6", "IP-ASN"):
                        self.ips.add(val)

    def is_covered(self, rtype: str, val: str) -> Tuple[bool, str]:
        """判断一个域名是否已经被本地规则有效覆盖（包括后缀与关键词匹配）"""
        if rtype == "DOMAIN":
            if val in self.exact_domains:
                return True, f"精确匹配 DOMAIN,{val}"
            for suf in self.suffix_domains:
                if val == suf or val.endswith("." + suf):
                    return True, f"被后缀规则 DOMAIN-SUFFIX,{suf} 覆盖"
            for kw in self.keywords:
                if kw in val:
                    return True, f"被关键字规则 DOMAIN-KEYWORD,{kw} 覆盖"
            return False, ""
        elif rtype == "DOMAIN-SUFFIX":
            if val in self.suffix_domains:
                return True, f"已有相同后缀 DOMAIN-SUFFIX,{val}"
            for suf in self.suffix_domains:
                if val.endswith("." + suf):
                    return True, f"已被更广后缀 DOMAIN-SUFFIX,{suf} 覆盖"
            return False, ""
        elif rtype == "DOMAIN-KEYWORD":
            if val in self.keywords:
                return True, f"已有关键字 DOMAIN-KEYWORD,{val}"
            return False, ""
        elif rtype in ("IP-CIDR", "IP-CIDR6", "IP-ASN"):
            if val in self.ips:
                return True, f"已有 IP/ASN 规则 {rtype},{val}"
            return False, ""
        return False, ""

def wash_target(target: str, repo_root: str) -> Dict:
    """对指定分类进行血库抓取与清洗比对"""
    if target not in RULE_SOURCES:
        raise ValueError(f"未知的目标分类: {target}。支持的分类: {list(RULE_SOURCES.keys())}")

    cfg = RULE_SOURCES[target]
    local_path = os.path.join(repo_root, cfg["local"])
    local = LocalRuleset(local_path)

    upstream_rules: List[Tuple[str, str, str]] = [] # (rtype, val, source_name)

    # 1. 抓取 v2fly
    for vname in cfg.get("v2fly", []):
        url = f"https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/{vname}"
        c = fetch_url(url)
        if c:
            for rtype, val in parse_v2fly(c):
                upstream_rules.append((rtype, val, f"v2fly/{vname}"))

    # 2. 抓取 blackmatrix7
    for bname in cfg.get("blackmatrix7", []):
        url = f"https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/{bname}/{bname}.list"
        c = fetch_url(url)
        if c:
            for rtype, val in parse_clash_list(c):
                # 剔除 blackmatrix7 在 Copilot 中偷懒打包的全套 OpenAI 域名
                if target == "copilot" and any(x in val for x in ("openai", "chatgpt", "sora", "oaiusercontent", "oaistatic", "crixet")):
                    continue
                upstream_rules.append((rtype, val, f"blackmatrix7/{bname}"))

    # 3. 抓取 Repcz
    for rname in cfg.get("repcz", []):
        url = f"https://raw.githubusercontent.com/Repcz/Tool/X/mihomo/Rules/{rname}.list"
        c = fetch_url(url)
        if c:
            for rtype, val in parse_clash_list(c):
                if rname == "AI":
                    kw_map = {
                        "claude": ["claude", "anthropic", "antspace", "claudemcp"],
                        "openai": ["openai", "chatgpt", "sora", "oai", "crixet", "searchgpt"],
                        "cursor": ["cursor", "anysphere"],
                        "copilot": ["copilot"],
                        "gemini": ["gemini", "bard", "makersuite", "generativelanguage", "aistudio", "deepmind"],
                        "perplexity": ["perplexity", "pplx"],
                        "grok": ["grok"],
                    }
                    if target in kw_map:
                        if not any(k in val for k in kw_map[target]):
                            continue
                upstream_rules.append((rtype, val, f"repcz/{rname}"))

    candidates: List[Dict] = []
    poisoned: List[Dict] = []
    already_covered: List[Dict] = []

    seen = set()

    for rtype, val, src in upstream_rules:
        key = (rtype, val)
        if key in seen:
            continue
        seen.add(key)

        covered, reason = local.is_covered(rtype, val)
        if covered:
            already_covered.append({"type": rtype, "value": val, "reason": reason, "source": src})
            continue

        # 检查是否触碰泛化主域名黑名单（防止抢占流量）
        is_poison = False
        if rtype == "DOMAIN-SUFFIX" and val in POISON_SUFFIX_BLACKLIST:
            is_poison = True
            poison_reason = f"高危泛化主域名 ({val})，禁止作为全量后缀加入特定策略组"

        if is_poison:
            poisoned.append({"type": rtype, "value": val, "reason": poison_reason, "source": src})
        else:
            candidates.append({"type": rtype, "value": val, "source": src})

    return {
        "target": target,
        "local_file": cfg["local"],
        "local_full_path": local_path,
        "total_upstream_fetched": len(upstream_rules),
        "candidates": candidates,
        "poisoned": poisoned,
        "already_covered_count": len(already_covered),
    }

def compile_list_to_mrs(list_path: str, mrs_path: str) -> bool:
    """利用本地 mihomo 编译规则集 .list 为二进制 .mrs"""
    domain_rules = []
    with open(list_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("//"):
                continue
            if line.startswith(("IP-CIDR", "IP-CIDR6", "IP-ASN", "PROCESS-NAME", "DOMAIN-KEYWORD")):
                continue
            line = line.split(",no-resolve")[0].strip()
            parts = [p.strip() for p in line.split(",")]
            if len(parts) >= 2:
                rtype = parts[0].upper()
                val = parts[1]
                if rtype == "DOMAIN-SUFFIX":
                    domain_rules.append(f"+.{val}")
                elif rtype == "DOMAIN":
                    domain_rules.append(val)

    if not domain_rules:
        return False

    with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False, suffix=".txt") as tmp:
        tmp.write("\n".join(domain_rules) + "\n")
        tmp_name = tmp.name

    try:
        mihomo_bin = shutil.which("mihomo") or shutil.which("clash")
        if not mihomo_bin:
            return False
        res = subprocess.run([mihomo_bin, "convert-ruleset", "domain", "text", tmp_name, mrs_path], capture_output=True, text=True)
        return res.returncode == 0
    except Exception as e:
        print(f"[!] 编译 MRS 失败: {e}")
        return False
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)

def update_file_with_candidates(filepath: str, candidates: List[Dict]):
    """将选中的候选域名注入到 local .list 文件，并重新计算统计头部与编译 MRS"""
    if not os.path.exists(filepath):
        print(f"[!] 文件不存在: {filepath}")
        return

    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    lines = content.splitlines()

    # 提取现有主体规则（去除元数据头部）
    body_lines = []
    in_header = True
    for line in lines:
        if in_header:
            if line.startswith("#") and any(line.startswith(p) for p in (
                "# NAME:", "# AUTHOR:", "# REPO:", "# UPDATED:",
                "# DOMAIN:", "# DOMAIN-SUFFIX:", "# DOMAIN-KEYWORD:",
                "# IP-CIDR:", "# IP-CIDR6:", "# IP-ASN:", "# TOTAL:"
            )):
                continue
            if line.strip() == "":
                continue
            in_header = False
        body_lines.append(line)

    # 准备新规则
    new_domains = [c["value"] for c in candidates if c["type"] == "DOMAIN"]
    new_suffixes = [c["value"] for c in candidates if c["type"] == "DOMAIN-SUFFIX"]
    new_keywords = [c["value"] for c in candidates if c["type"] == "DOMAIN-KEYWORD"]
    new_ips = [c["value"] for c in candidates if c["type"] in ("IP-CIDR", "IP-CIDR6", "IP-ASN")]

    # 找到相应的位置插入
    updated_body = []
    added_suffixes = False
    added_domains = False

    for line in body_lines:
        sline = line.strip()
        if sline.startswith("# 域名后缀") or sline == "# 域名后缀":
            updated_body.append(line)
            if new_suffixes and not added_suffixes:
                for s in new_suffixes:
                    updated_body.append(f"DOMAIN-SUFFIX,{s}")
                added_suffixes = True
            continue
        elif sline.startswith("# 核心域名") or sline == "# 核心域名":
            updated_body.append(line)
            if new_domains and not added_domains:
                for d in new_domains:
                    updated_body.append(f"DOMAIN,{d}")
                added_domains = True
            continue
        updated_body.append(line)

    if new_suffixes and not added_suffixes:
        updated_body.append("\n# 域名后缀 (洗血补充)")
        for s in new_suffixes:
            updated_body.append(f"DOMAIN-SUFFIX,{s}")
    if new_domains and not added_domains:
        updated_body.append("\n# 核心域名 (洗血补充)")
        for d in new_domains:
            updated_body.append(f"DOMAIN,{d}")
    if new_ips:
        updated_body.append("\n# IP/ASN 规则 (洗血补充)")
        for ip in new_ips:
            updated_body.append(f"IP-CIDR,{ip},no-resolve")

    # 统计所有有效规则
    counts = {
        "DOMAIN": 0,
        "DOMAIN-SUFFIX": 0,
        "DOMAIN-KEYWORD": 0,
        "IP-CIDR": 0,
        "IP-CIDR6": 0,
        "IP-ASN": 0,
    }
    for l in updated_body:
        sl = l.strip()
        if not sl or sl.startswith("#") or sl.startswith("//"):
            continue
        p = [x.strip() for x in sl.split(",")]
        if len(p) >= 2:
            t = p[0].upper()
            if t in counts:
                counts[t] += 1

    total = sum(counts.values())

    # 生成规范化 Header
    rule_name = os.path.splitext(os.path.basename(filepath))[0]
    today = datetime.now().strftime("%Y-%m-%d")

    header_lines = [
        f"# NAME: {rule_name}",
        "# AUTHOR: Hexon",
        "# REPO: https://github.com/HexTTX/Hex-Clash",
        f"# UPDATED: {today}",
    ]
    if counts["DOMAIN"] > 0:
        header_lines.append(f"# DOMAIN: {counts['DOMAIN']}")
    if counts["DOMAIN-KEYWORD"] > 0:
        header_lines.append(f"# DOMAIN-KEYWORD: {counts['DOMAIN-KEYWORD']}")
    if counts["DOMAIN-SUFFIX"] > 0:
        header_lines.append(f"# DOMAIN-SUFFIX: {counts['DOMAIN-SUFFIX']}")
    if counts["IP-CIDR"] > 0:
        header_lines.append(f"# IP-CIDR: {counts['IP-CIDR']}")
    if counts["IP-CIDR6"] > 0:
        header_lines.append(f"# IP-CIDR6: {counts['IP-CIDR6']}")
    if counts["IP-ASN"] > 0:
        header_lines.append(f"# IP-ASN: {counts['IP-ASN']}")
    header_lines.append(f"# TOTAL: {total}\n")

    final_content = "\n".join(header_lines) + "\n" + "\n".join(updated_body) + "\n"

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(final_content)

    print(f"[✓] 已更新本地规则文件: {filepath} (条目总计: {total})")

    # 编译 MRS
    mrs_path = os.path.splitext(filepath)[0] + ".mrs"
    if compile_list_to_mrs(filepath, mrs_path):
        mrs_size = os.path.getsize(mrs_path)
        print(f"[✓] 本地 MRS 编译成功: {mrs_path} ({mrs_size} bytes)")
    else:
        print(f"[i] 跳过本地 MRS 编译 (或由 GitHub Actions 自动构建)")

def main():
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    args = sys.argv[1:]

    apply_mode = False
    if "--apply" in args:
        apply_mode = True
        args.remove("--apply")

    targets = args if args else ["claude", "openai", "copilot", "cursor", "gemini", "grok", "check"]

    print("=" * 70)
    print("  Hex-Clash 自建规则库洗血与补漏分析引擎")
    if apply_mode:
        print("  【应用模式 (APPLY MODE)】：比对完成后将优质候选条目自动写入本地规则并编译 MRS")
    print("=" * 70)

    for target in targets:
        print(f"\n[*] 正在清洗比对分类: 【{target.upper()}】...")
        try:
            report = wash_target(target, repo_root)
        except Exception as e:
            print(f"[!] 发生错误: {e}")
            continue

        print(f"  - 本地规则文件: {report['local_file']}")
        print(f"  - 抓取上游条目: {report['total_upstream_fetched']} 条")
        print(f"  - 已被本地覆盖: {report['already_covered_count']} 条 (命中已有后缀或关键词)")

        if report['poisoned']:
            print(f"  - 拦截高危泛化域名 (防污染): {len(report['poisoned'])} 条")
            for p in report['poisoned']:
                print(f"      [拦截] {p['type']},{p['value']}  <- 来自 {p['source']} ({p['reason']})")

        print(f"  - 发现新鲜血液 (候选新增): {len(report['candidates'])} 条")
        if report['candidates']:
            for c in report['candidates']:
                print(f"      [+候选] {c['type']},{c['value']}  (来自 {c['source']})")

            if apply_mode:
                update_file_with_candidates(report["local_full_path"], report["candidates"])
        else:
            print("      (当前本地库已非常全面，暂无漏网优质域名)")

    print("\n" + "=" * 70)
    print("清洗比对工作结束。")

if __name__ == "__main__":
    main()
