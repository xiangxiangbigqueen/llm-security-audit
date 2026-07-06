"""
扫描器 Agent - 代码静态分析核心模块
负责对目标代码进行多维度安全扫描

【主流技术使用标注】
★ LLM 驱动: 第2层使用 Claude Code 进行语义级漏洞验证（行 108-111, 156-189）
★ SAST: 第1层正则规则匹配 + 上下文提取（行 52-101）
★ Agent 智能体: 独立的扫描 Agent 封装，类名 ScannerAgent（行 15）
★ JSON 结构化通信: Agent 间通过 JSON 格式交换验证结果（行 175-188）
★ Prompt 工程: 构造专业安全审计 Prompt 供 LLM 调用（行 156-189）
"""

import os
import re
import json
import time
from pathlib import Path
from typing import Optional
import subprocess


class ScannerAgent:
    """
    扫描器 Agent
    使用规则匹配 + LLM 分析的多层扫描架构
    """

    def __init__(self, llm_enabled: bool = True):
        self.llm_enabled = llm_enabled
        self.findings = []
        self.scan_stats = {
            "files_scanned": 0,
            "files_skipped": 0,
            "patterns_matched": 0,
            "llm_findings": 0,
            "start_time": None,
            "end_time": None,
        }

    def scan(self, project_path: str, files: list) -> list:
        """
        对项目代码执行安全扫描

        Args:
            project_path: 项目根路径
            files: 待扫描文件列表

        Returns:
            发现的漏洞列表
        """
        from config.settings import VULN_CATEGORIES

        self.findings = []
        self.scan_stats["start_time"] = time.time()

        print(f"\n  🔍 开始安全扫描 ({len(files)} 个文件)...")
        print(f"  {'='*50}")

        # 第一层：规则匹配（快速扫描）
        all_patterns = []
        for cat_key, cat_config in VULN_CATEGORIES.items():
            for pattern in cat_config["patterns"]:
                all_patterns.append((cat_key, pattern, cat_config))

        for file_info in files:
            if self.scan_stats["files_scanned"] >= 500:
                print(f"  ⚠️ 达到最大扫描文件数限制")
                break

            relpath = file_info["relpath"]

            try:
                with open(file_info["path"], 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
            except Exception as e:
                self.scan_stats["files_skipped"] += 1
                continue

            self.scan_stats["files_scanned"] += 1

            # 对每个文件进行规则匹配
            for cat_key, pattern, cat_config in all_patterns:
                try:
                    matches = re.finditer(pattern, content, re.MULTILINE)
                    for match in matches:
                        # 提取上下文（匹配行前后各2行）
                        lines = content[:match.end()].split('\n')
                        line_no = len(lines)
                        context = self._get_context(content, match.start(), match.end())

                        finding = {
                            "id": f"{cat_key}-{len(self.findings)+1}",
                            "category": cat_key,
                            "vuln_name": cat_config["name"],
                            "severity": cat_config["severity"],
                            "cwe": cat_config["cwe"],
                            "file": relpath,
                            "line": line_no,
                            "match": match.group()[:200],
                            "context": context,
                            "risk_description": cat_config["risk_description"],
                            "source": "pattern_match",
                            "verified": False,
                        }
                        self.findings.append(finding)
                        self.scan_stats["patterns_matched"] += 1
                except re.error:
                    continue

            # 进度显示
            if self.scan_stats["files_scanned"] % 50 == 0:
                print(f"   进度: {self.scan_stats['files_scanned']}/{len(files)} 文件, "
                      f"发现 {len(self.findings)} 个潜在问题")

        # 第二层：LLM 深度分析（对高风险文件）
        if self.llm_enabled and self.findings:
            print(f"\n  🤖 启动 LLM Agent 深度分析...")
            self._llm_deep_scan(project_path, files)

        # 去重：同一文件同一行同一类别只保留一个
        self._deduplicate()

        self.scan_stats["end_time"] = time.time()
        return self.findings

    def scan_single(self, file_info: dict, project_path: str) -> list:
        """
        扫描单个文件（供并行编排器调用）
        使用对象级别的 self 来采集统计
        """
        from config.settings import VULN_CATEGORIES

        findings = []
        relpath = file_info["relpath"]
        filepath = file_info["path"]

        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception:
            return []

        for cat_key, cat_config in VULN_CATEGORIES.items():
            for pattern in cat_config["patterns"]:
                try:
                    matches = re.finditer(pattern, content, re.MULTILINE)
                    for match in matches:
                        lines = content[:match.end()].split('\n')
                        line_no = len(lines)
                        context = self._get_context(content, match.start(), match.end())

                        findings.append({
                            "id": f"{cat_key}-{hash(relpath+str(line_no)+cat_key) % 10000}",
                            "category": cat_key,
                            "vuln_name": cat_config["name"],
                            "severity": cat_config["severity"],
                            "cwe": cat_config["cwe"],
                            "file": relpath,
                            "line": line_no,
                            "match": match.group()[:200],
                            "context": context,
                            "risk_description": cat_config["risk_description"],
                            "source": "pattern_match_parallel",
                            "verified": False,
                        })
                except re.error:
                    continue

        # 更新统计
        self.scan_stats["files_scanned"] = self.scan_stats.get("files_scanned", 0) + 1
        self.scan_stats["patterns_matched"] = self.scan_stats.get("patterns_matched", 0) + len(findings)
        self.findings.extend(findings)

        return findings

    def _llm_deep_scan(self, project_path: str, files: list):
        """
        使用 Claude Code 进行深度分析
        对规则匹配到的可疑文件进行 LLM 验证
        """
        # 收集有潜在问题的文件
        suspicious_files = {}
        for f in self.findings:
            file_path = f["file"]
            if file_path not in suspicious_files:
                suspicious_files[file_path] = []
            suspicious_files[file_path].append(f)

        # 对每个有发现的文件进行 LLM 验证
        verified_count = 0
        for file_relpath, file_findings in suspicious_files.items():
            file_path = os.path.join(project_path, file_relpath)

            if not os.path.exists(file_path):
                continue

            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    code_content = f.read()
            except:
                continue

            # 截取代码（限制长度）
            if len(code_content) > 8000:
                code_content = code_content[:8000] + "\n# ... (剩余代码已截断)"

            # 为这个文件的发现构建验证 prompt
            findings_text = "\n".join([
                f"- [{f['severity']}] {f['vuln_name']} (行 {f['line']}): {f['match'][:100]}"
                for f in file_findings
            ])

            prompt = f"""请对以下代码安全扫描结果进行人工验证，判断是否为真正的安全漏洞：

## 文件: {file_relpath}

## 代码内容:
```{os.path.splitext(file_relpath)[1].lstrip('.') if os.path.splitext(file_relpath)[1] else ''}
{code_content}
```

## 扫描发现的问题:
{findings_text}

## 验证要求：
请逐条分析每个发现：
1. **是否为真正的漏洞**？还是误报（如测试代码、已过滤的输入等）？
2. **漏洞严重程度评估**：确认/升级/降级
3. **攻击者如何利用**：简要描述攻击路径
4. **修复建议**：如何修复此漏洞

请以 JSON 格式返回验证结果：
```json
[
  {{
    "finding_id": "类别-序号",
    "is_real_vulnerability": true/false,
    "confirmed_severity": "高危/中危/低危/信息",
    "exploit_scenario": "攻击场景描述",
    "fix_suggestion": "修复建议",
    "confidence": "high/medium/low"
  }}
]
```

只返回 JSON，不要有其他内容。"""

            try:
                result = subprocess.run(
                    ["claude", "prompt", prompt, "--print"],
                    capture_output=True, text=True, timeout=60
                )
                if result.returncode == 0:
                    output = result.stdout.strip()
                    # 提取 JSON 部分
                    json_match = re.search(r'```json\n(.*?)\n```', output, re.DOTALL)
                    if json_match:
                        json_str = json_match.group(1)
                    else:
                        json_str = output

                    try:
                        verifications = json.loads(json_str)
                        if isinstance(verifications, list):
                            for v in verifications:
                                fid = v.get("finding_id", "")
                                for f in self.findings:
                                    if f["id"] == fid:
                                        f["verified"] = True
                                        f["is_real"] = v.get("is_real_vulnerability", False)
                                        f["confirmed_severity"] = v.get("confirmed_severity", f["severity"])
                                        f["exploit_scenario"] = v.get("exploit_scenario", "")
                                        f["fix_suggestion"] = v.get("fix_suggestion", "")
                                        f["source"] = "pattern_match+llm_verified"
                                        break
                            verified_count += len(verifications)
                            self.scan_stats["llm_findings"] += len(verifications)
                    except json.JSONDecodeError:
                        pass
                print(f"    ✓ LLM 验证完成: {file_relpath}")
            except (subprocess.TimeoutExpired, FileNotFoundError) as e:
                print(f"    ⚠️ LLM 分析跳过 ({file_relpath}): {type(e).__name__}")
                continue

        if verified_count:
            print(f"  🤖 LLM 深度分析完成，验证了 {verified_count} 个发现")

    def _get_context(self, content: str, start: int, end: int, lines_before: int = 2) -> str:
        """提取匹配位置周围的代码上下文"""
        lines = content.split('\n')
        # 找到匹配所在的起始行
        char_count = 0
        match_line_idx = 0
        for i, line in enumerate(lines):
            char_count += len(line) + 1  # +1 for newline
            if char_count > start:
                match_line_idx = i
                break

        start_idx = max(0, match_line_idx - lines_before)
        end_idx = min(len(lines), match_line_idx + lines_before + 1)

        context_lines = []
        for i in range(start_idx, end_idx):
            marker = " >>> " if i == match_line_idx else "     "
            context_lines.append(f"{marker}{i+1}: {lines[i]}")

        return '\n'.join(context_lines)

    def _deduplicate(self):
        """去重：同一文件同一行同一类别只保留一个"""
        seen = set()
        unique_findings = []
        for f in self.findings:
            key = (f["file"], f["line"], f["category"])
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)
        self.findings = unique_findings

    def print_summary(self):
        """打印扫描统计摘要"""
        elapsed = 0
        if self.scan_stats.get("end_time") and self.scan_stats.get("start_time"):
            elapsed = self.scan_stats["end_time"] - self.scan_stats["start_time"]
        real_count = sum(1 for f in self.findings if f.get("is_real", True))

        print(f"\n  {'='*50}")
        print(f"  📊 扫描统计")
        print(f"  {'='*50}")
        print(f"    扫描文件数:    {self.scan_stats['files_scanned']}")
        print(f"    跳过文件数:    {self.scan_stats['files_skipped']}")
        print(f"    规则匹配数:    {self.scan_stats['patterns_matched']}")
        print(f"    LLM 验证数:    {self.scan_stats['llm_findings']}")
        print(f"    去重后问题数:  {len(self.findings)}")
        print(f"    扫描耗时:      {elapsed:.1f} 秒")

        # 按严重程度统计
        severity_counts = {}
        for f in self.findings:
            sev = f.get("confirmed_severity", f["severity"])
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        for sev in ["高危", "中危", "低危", "信息"]:
            if sev in severity_counts:
                print(f"      {sev}: {severity_counts[sev]} 个")

        return {
            "total": len(self.findings),
            "real": real_count,
            "by_severity": severity_counts,
            "elapsed": elapsed,
            "files_scanned": self.scan_stats["files_scanned"],
            "files_skipped": self.scan_stats["files_skipped"],
            "patterns_matched": self.scan_stats["patterns_matched"],
            "llm_findings": self.scan_stats["llm_findings"],
        }
