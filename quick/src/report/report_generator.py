"""
报告生成模块
生成结构化安全审计报告（Markdown / HTML / JSON）

【主流技术使用标注】
★ 结构化报告: 同时输出 MD + JSON + HTML 三种格式
★ 证据链输出: 每个漏洞附带完整证据链（位置、调用路径、验证结果）
★ CWE 标准: 漏洞关联 CWE 编号和风险评估
★ 修复建议: 每类漏洞附带可操作的修复方案
"""

import os
import json
import datetime
import html
from typing import Optional
from collections import Counter


def _escape_html(obj):
    """递归 HTML 转义 dict/list/str 中的所有字符串值，防止 XSS"""
    if isinstance(obj, str):
        return html.escape(obj)
    if isinstance(obj, dict):
        return {k: _escape_html(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_escape_html(v) for v in obj]
    return obj


class ReportGenerator:
    """
    安全审计报告生成器
    支持 Markdown、JSON、HTML 三种格式
    """

    def __init__(self, output_dir: str = "reports"):
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

        # 报告元数据
        self.metadata = {
            "tool_name": "LLM Security Audit System - SAST",
            "version": "1.0.0",
            "scan_date": None,
            "target": None,
            "project_info": None,
            "summary": None,
        }

    def generate(self, findings: list, project_info: dict, scan_stats: dict) -> dict:
        """
        生成完整的安全审计报告

        Args:
            findings: 所有扫描发现
            project_info: 项目信息
            scan_stats: 扫描统计

        Returns:
            报告文件路径字典 {format: path}
        """
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        project_name = project_info.get("name", "unknown")
        base_name = f"security_report_{project_name}_{timestamp}"

        # 准备报告数据
        report_data = self._prepare_report_data(findings, project_info, scan_stats, timestamp)

        # 生成各格式报告
        output_paths = {}

        # Markdown
        md_path = os.path.join(self.output_dir, f"{base_name}.md")
        self._generate_markdown(report_data, md_path)
        output_paths["markdown"] = md_path
        print(f"\n  📄 Markdown 报告: {md_path}")

        # JSON
        json_path = os.path.join(self.output_dir, f"{base_name}.json")
        self._generate_json(report_data, json_path)
        output_paths["json"] = json_path
        print(f"  📄 JSON 报告: {json_path}")

        # HTML
        html_path = os.path.join(self.output_dir, f"{base_name}.html")
        self._generate_html(report_data, html_path)
        output_paths["html"] = html_path
        print(f"  📄 HTML 报告: {html_path}")

        return output_paths

    def _prepare_report_data(self, findings, project_info, scan_stats, timestamp):
        """整理报告数据"""
        # 按严重程度分组
        severity_groups = {"高危": [], "中危": [], "低危": [], "信息": []}
        for f in findings:
            sev = f.get("confirmed_severity", f.get("severity", "信息"))
            if sev not in severity_groups:
                sev = "信息"
            severity_groups[sev].append(f)

        # 按漏洞类型统计
        type_counts = Counter(f["vuln_name"] for f in findings)

        # 按文件统计
        file_counts = Counter(f["file"] for f in findings)

        return {
            "metadata": {
                "tool": "LLM Security Audit System",
                "version": "1.0.0",
                "scan_date": timestamp,
                "generated_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            },
            "project": {
                "name": project_info.get("name", "N/A"),
                "path": project_info.get("path", "N/A"),
                "source": project_info.get("source", "N/A"),
                "languages": project_info.get("languages", {}),
                "description": project_info.get("description", ""),
            },
            "summary": {
                "total_findings": len(findings),
                "confirmed_real": sum(1 for f in findings if f.get("is_real", True)),
                "by_severity": {sev: len(items) for sev, items in severity_groups.items()},
                "by_type": dict(type_counts.most_common()),
                "by_file": dict(file_counts.most_common(10)),
                "scan_stats": scan_stats,
            },
            "findings": findings,
            "severity_groups": severity_groups,
        }

    def _generate_markdown(self, data: dict, output_path: str):
        """生成 Markdown 格式报告"""
        lines = []

        # 标题
        lines.append("# 🔒 安全审计报告")
        lines.append("")
        lines.append(f"**工具**: {data['metadata']['tool']} v{data['metadata']['version']}")
        lines.append(f"**扫描时间**: {data['metadata']['scan_date']}")
        lines.append(f"**报告生成**: {data['metadata']['generated_at']}")
        lines.append("")

        # 项目信息
        lines.append("## 📂 项目信息")
        lines.append("")
        lines.append(f"- **项目名称**: {data['project']['name']}")
        lines.append(f"- **项目路径**: `{data['project']['path']}`")
        lines.append(f"- **项目来源**: {data['project']['source']}")
        langs = data['project']['languages']
        if langs:
            lines.append(f"- **编程语言**: {', '.join(f'{k}({v})' for k, v in langs.items())}")
        lines.append("")

        # 摘要
        lines.append("## 📊 扫描摘要")
        lines.append("")
        summary = data['summary']
        lines.append(f"| 指标 | 数值 |")
        lines.append(f"|------|------|")
        lines.append(f"| 总发现数 | {summary['total_findings']} |")
        lines.append(f"| 确认漏洞 | {summary['confirmed_real']} |")

        lines.append(f"| 高危 | {summary['by_severity'].get('高危', 0)} |")
        lines.append(f"| 中危 | {summary['by_severity'].get('中危', 0)} |")
        lines.append(f"| 低危 | {summary['by_severity'].get('低危', 0)} |")
        lines.append(f"| 信息 | {summary['by_severity'].get('信息', 0)} |")

        ss = summary.get('scan_stats', {})
        if ss:
            lines.append(f"| 扫描文件数 | {ss.get('files_scanned', 0)} |")
            lines.append(f"| 匹配规则数 | {ss.get('patterns_matched', 0)} |")
        lines.append("")

        # 按严重程度的漏洞详情
        lines.append("## 🐛 漏洞详情")
        lines.append("")

        for severity in ["高危", "中危", "低危", "信息"]:
            findings = data['severity_groups'].get(severity, [])
            if not findings:
                continue

            lines.append(f"### {'🔴' if severity=='高危' else '🟡' if severity=='中危' else '🟢' if severity=='低危' else '🔵'} {severity} ({len(findings)} 个)")
            lines.append("")

            for f in findings:
                lines.append(f"#### {f['vuln_name']} — `{f['file']}:{f['line']}`")
                lines.append("")
                lines.append(f"- **漏洞ID**: {f['id']}")
                lines.append(f"- **CWE**: {f.get('cwe', 'N/A')}")
                lines.append(f"- **风险描述**: {f.get('risk_description', 'N/A')}")
                lines.append(f"- **匹配内容**: `{f.get('match', '')[:150]}`")
                lines.append("")

                if f.get('exploit_scenario'):
                    lines.append(f"- **攻击场景**: {f['exploit_scenario']}")
                if f.get('fix_suggestion'):
                    lines.append(f"- **修复建议**: {f['fix_suggestion']}")
                lines.append("")

                # 代码上下文
                if f.get('context'):
                    lines.append("```")
                    lines.append(f.get('context', ''))
                    lines.append("```")
                    lines.append("")

                # === 🆕 证据链（新增） ===
                poc = f.get('poc', {})
                evidence = poc.get('evidence_chain', {}) if isinstance(poc, dict) else {}

                if evidence:
                    lines.append("#### 🔗 证据链")
                    lines.append("")
                    # 1. 文件位置
                    lines.append("**① 文件位置**")
                    loc = evidence.get('file_location', {})
                    lines.append(f"- 文件: `{loc.get('file', '')}`")
                    lines.append(f"- 行号: {loc.get('line', 0)}")
                    lines.append("")
                    # 2. 调用路径
                    call_path = evidence.get('call_path', [])
                    if call_path:
                        lines.append("**② 调用路径（输入源 → 危险函数）**")
                        lines.append("```")
                        for step in call_path[-8:]:  # 最近 8 步
                            lines.append(f"  [{step.get('step','?')}] 行 {step.get('line','?')}: {step.get('code','')}")
                        lines.append("```")
                        lines.append(f"- **输入源**: {evidence.get('input_source', '未知')}")
                        lines.append(f"- **危险函数**: {evidence.get('sink_function', '未知')}")
                        lines.append("")
                    # 3. 验证结果
                    ver = evidence.get('verification', {})
                    lines.append("**③ 验证结果**")
                    lines.append(f"- **真实性**: {'✅ 确认漏洞' if ver.get('is_real') else '❌ 误报'}")
                    lines.append(f"- **严重程度**: {ver.get('confirmed_severity', '未知')}")
                    lines.append(f"- **可利用性**: {poc.get('exploitability', '需要验证')}")
                    lines.append("")
                    # 4. 证据完整性
                    integrity = evidence.get('evidence_integrity', {})
                    if integrity:
                        passed = sum(v for v in integrity.values() if isinstance(v, bool))
                        total = sum(1 for v in integrity.values() if isinstance(v, bool))
                        lines.append(f"**④ 证据完整性**: {passed}/{total}")
                        lines.append("")

                # PoC 代码
                if isinstance(poc, dict) and poc.get('poc_code'):
                    lines.append("**💥 PoC 利用代码**")
                    lines.append(f"```python")
                    lines.append(poc['poc_code'][:500])
                    lines.append("```")
                    lines.append("")

                lines.append("---")
                lines.append("")

        # 漏洞类型分布
        lines.append("## 📈 漏洞类型分布")
        lines.append("")
        lines.append("| 漏洞类型 | 数量 |")
        lines.append("|----------|------|")
        for vuln_type, count in summary.get('by_type', {}).items():
            lines.append(f"| {vuln_type} | {count} |")
        lines.append("")

        # 修复建议汇总
        lines.append("## 💡 通用修复建议")
        lines.append("")
        lines.append("### SQL 注入")
        lines.append("- 使用参数化查询或 PreparedStatement")
        lines.append("- 对用户输入进行严格的类型检查和过滤")
        lines.append("- 最小化数据库账户权限")
        lines.append("")
        lines.append("### 命令注入")
        lines.append("- 避免使用 shell=True 或系统命令拼接")
        lines.append("- 使用白名单机制验证用户输入")
        lines.append("- 以最小权限运行应用程序")
        lines.append("")
        lines.append("### XSS")
        lines.append("- 对输出进行 HTML 实体编码")
        lines.append("- 使用 Content-Security-Policy 头")
        lines.append("- 避免使用 innerHTML、v-html 等危险方法")
        lines.append("")
        lines.append("### 硬编码密钥")
        lines.append("- 使用环境变量或密钥管理服务 (Vault, AWS Secrets Manager)")
        lines.append("- 使用 .gitignore 排除配置文件")
        lines.append("- 定期轮换密钥")
        lines.append("")

        lines.append("---")
        lines.append("")
        lines.append(f"*报告由 {data['metadata']['tool']} 自动生成*")

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))

    def _generate_json(self, data: dict, output_path: str):
        """生成 JSON 格式报告"""
        # 移除不可序列化的大段内容
        report = {
            "tool": data['metadata']['tool'],
            "version": data['metadata']['version'],
            "scan_date": data['metadata']['scan_date'],
            "generated_at": data['metadata']['generated_at'],
            "project": data['project'],
            "summary": data['summary'],
            "findings": [],
        }

        for f in data['findings']:
            finding = {
                "id": f["id"],
                "vuln_name": f["vuln_name"],
                "category": f["category"],
                "severity": f.get("confirmed_severity", f["severity"]),
                "cwe": f.get("cwe", ""),
                "file": f["file"],
                "line": f["line"],
                "match": f.get("match", "")[:200],
                "risk_description": f.get("risk_description", ""),
                "is_real": f.get("is_real", True),
                "exploit_scenario": f.get("exploit_scenario", ""),
                "fix_suggestion": f.get("fix_suggestion", ""),
                "has_poc": f.get("has_poc", False),
            }
            report["findings"].append(finding)

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, ensure_ascii=False, indent=2)

    def _generate_html(self, data: dict, output_path: str):
        """生成 HTML 格式报告（增强版）"""
        # HTML 转义所有代码内容，防止报告中嵌入的漏洞代码被浏览器执行
        data["findings"] = _escape_html(data["findings"])
        for sev in data["severity_groups"]:
            data["severity_groups"][sev] = _escape_html(data["severity_groups"][sev])

        html = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Audit Report - {project_name}</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, 'Microsoft YaHei', 'Segoe UI', sans-serif; background: #0f0f23; color: #e0e0e0; }}
        .container {{ max-width: 1300px; margin: 0 auto; padding: 20px; }}

        /* Navigation */
        .nav {{ position: sticky; top: 0; z-index: 100; background: #1a1a3e; border-bottom: 1px solid #2a2a4a; padding: 8px 20px; margin: -20px -20px 20px; display: flex; gap: 8px; flex-wrap: wrap; }}
        .nav a {{ color: #888; text-decoration: none; font-size: 12px; padding: 6px 12px; border-radius: 4px; }}
        .nav a:hover {{ color: #00d4ff; background: #2a2a4a; }}
        .nav .badge {{ display: inline-block; padding: 1px 6px; border-radius: 3px; font-size: 10px; margin-left: 4px; }}

        /* Header */
        .header {{ background: linear-gradient(135deg, #1a1a2e, #16213e); border: 1px solid #2a2a4a; border-radius: 16px; padding: 30px 40px; margin-bottom: 24px; }}
        .header h1 {{ font-size: 28px; background: linear-gradient(135deg, #00d4ff, #7b2ff7); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }}
        .header .meta {{ margin-top: 12px; font-size: 13px; color: #888; display: flex; flex-wrap: wrap; gap: 16px; }}

        /* Risk Score */
        .risk-meter {{ display: flex; align-items: center; gap: 16px; padding: 16px; border-radius: 10px; margin-bottom: 16px; background: #0f0f23; border: 1px solid #2a2a4a; }}
        .risk-score {{ font-size: 48px; font-weight: bold; line-height: 1; }}
        .risk-score.critical {{ color: #dc3545; }}
        .risk-score.high {{ color: #fd7e14; }}
        .risk-score.medium {{ color: #ffc107; }}
        .risk-score.low {{ color: #28a745; }}
        .risk-detail {{ font-size: 13px; color: #aaa; }}
        .risk-bar {{ flex: 1; height: 8px; border-radius: 4px; background: #2a2a4a; overflow: hidden; }}
        .risk-bar-fill {{ height: 100%; border-radius: 4px; transition: width 1s; }}

        /* Cards */
        .card {{ background: #1a1a3e; border: 1px solid #2a2a4a; border-radius: 12px; padding: 24px; margin-bottom: 16px; }}
        .card h2 {{ font-size: 18px; margin-bottom: 16px; padding-bottom: 8px; border-bottom: 1px solid #2a2a4a; color: #00d4ff; }}
        .card h3 {{ font-size: 15px; margin: 16px 0 8px; color: #e0e0e0; }}

        /* Summary Grid */
        .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(110px, 1fr)); gap: 10px; }}
        .stat-card {{ text-align: center; padding: 16px 10px; border-radius: 10px; }}
        .stat-card.critical {{ background: rgba(220,53,69,0.15); border: 1px solid rgba(220,53,69,0.3); }}
        .stat-card.high {{ background: rgba(253,126,20,0.15); border: 1px solid rgba(253,126,20,0.3); }}
        .stat-card.medium {{ background: rgba(255,193,7,0.15); border: 1px solid rgba(255,193,7,0.3); }}
        .stat-card.low {{ background: rgba(40,167,69,0.15); border: 1px solid rgba(40,167,69,0.3); }}
        .stat-card.info {{ background: rgba(13,110,253,0.15); border: 1px solid rgba(13,110,253,0.3); }}
        .stat-card.total {{ background: rgba(108,117,125,0.15); border: 1px solid rgba(108,117,125,0.3); }}
        .stat-number {{ font-size: 32px; font-weight: bold; }}
        .stat-card.critical .stat-number {{ color: #dc3545; }}
        .stat-card.high .stat-number {{ color: #fd7e14; }}
        .stat-card.medium .stat-number {{ color: #ffc107; }}
        .stat-card.low .stat-number {{ color: #28a745; }}
        .stat-card.info .stat-number {{ color: #0d6efd; }}
        .stat-card.total .stat-number {{ color: #6c757d; }}
        .stat-label {{ font-size: 11px; color: #888; margin-top: 4px; }}

        /* Info Table */
        .info-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 4px 24px; font-size: 13px; }}
        .info-grid .label {{ color: #888; }}
        .info-grid .value {{ color: #e0e0e0; }}
        .info-row {{ display: flex; justify-content: space-between; padding: 4px 0; border-bottom: 1px solid #2a2a4a; }}

        /* Tables */
        table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
        th, td {{ padding: 8px 12px; text-align: left; border-bottom: 1px solid #2a2a4a; }}
        th {{ color: #888; font-weight: 600; font-size: 11px; text-transform: uppercase; cursor: pointer; }}
        th:hover {{ color: #00d4ff; }}
        tr:hover {{ background: rgba(255,255,255,0.02); }}

        /* Tags */
        .tag {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; }}
        .tag.critical {{ background: #dc3545; color: white; }}
        .tag.high {{ background: #fd7e14; color: white; }}
        .tag.medium {{ background: #ffc107; color: #333; }}
        .tag.low {{ background: #28a745; color: white; }}
        .tag.cwe {{ background: #6f42c1; color: white; }}
        .tag.info {{ background: #2a2a4a; color: #aaa; }}

        /* Findings */
        .finding {{ border: 1px solid #2a2a4a; border-left: 4px solid #555; margin-bottom: 12px; border-radius: 0 10px 10px 0; background: #0f0f23; }}
        .finding-header {{ display: flex; justify-content: space-between; align-items: center; padding: 12px 16px; cursor: pointer; }}
        .finding-header:hover {{ background: rgba(255,255,255,0.02); }}
        .finding.critical {{ border-left-color: #dc3545; }}
        .finding.high {{ border-left-color: #fd7e14; }}
        .finding.medium {{ border-left-color: #ffc107; }}
        .finding.low {{ border-left-color: #28a745; }}
        .finding-title {{ font-size: 14px; font-weight: 600; }}
        .finding-file {{ font-family: 'Courier New', monospace; font-size: 11px; color: #666; margin-left: 8px; }}
        .finding-body {{ padding: 0 16px 16px; display: none; }}
        .finding-body.open {{ display: block; }}

        /* Code block */
        .code-block {{ background: #0a0a1a; border: 1px solid #2a2a4a; border-radius: 8px; overflow: hidden; margin-top: 8px; }}
        .code-block .code-header {{ padding: 6px 12px; background: #1a1a3e; font-size: 11px; color: #888; border-bottom: 1px solid #2a2a4a; }}
        .code-block pre {{ padding: 12px; overflow-x: auto; font-size: 12px; line-height: 1.5; font-family: 'Courier New', monospace; margin: 0; }}
        .code-block .hl {{ background: rgba(220,53,69,0.15); display: block; }}

        /* Evidence */
        .evidence {{ background: #0a0a1a; border: 1px solid #2a2a4a; border-radius: 8px; padding: 12px; margin-top: 8px; }}
        .evidence-grid {{ display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 8px; }}
        .ev-item {{ padding: 8px; border-radius: 6px; background: #1a1a3e; font-size: 12px; }}
        .ev-item .ev-label {{ color: #888; font-size: 11px; }}
        .ev-item .ev-value {{ color: #e0e0e0; font-weight: 600; }}
        .path-step {{ padding: 3px 0; font-size: 12px; border-left: 2px solid #2a2a4a; padding-left: 10px; margin: 2px 0; }}
        .path-step:hover {{ border-left-color: #00d4ff; background: rgba(0,212,255,0.05); }}

        /* Flow chart */
        .flow {{ display: flex; align-items: center; gap: 8px; flex-wrap: wrap; padding: 8px; background: #1a1a3e; border-radius: 8px; margin-top: 8px; font-size: 12px; }}
        .flow-node {{ padding: 4px 10px; border-radius: 4px; background: #2a2a4a; }}
        .flow-node.source {{ background: rgba(220,53,69,0.2); border: 1px solid rgba(220,53,69,0.3); }}
        .flow-node.sink {{ background: rgba(253,126,20,0.2); border: 1px solid rgba(253,126,20,0.3); }}
        .flow-arrow {{ color: #555; }}

        /* Download bar */
        .download-bar {{ display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 16px; }}
        .download-btn {{ padding: 8px 16px; border-radius: 6px; border: 1px solid #2a2a4a; background: #1a1a3e; color: #e0e0e0; text-decoration: none; font-size: 13px; }}
        .download-btn:hover {{ border-color: #00d4ff; color: #00d4ff; }}

        /* Tabs */
        .tabs {{ display: flex; gap: 2px; margin-bottom: 12px; }}
        .tab {{ padding: 8px 16px; border-radius: 6px 6px 0 0; background: #1a1a3e; border: 1px solid #2a2a4a; cursor: pointer; font-size: 12px; color: #888; }}
        .tab.active {{ background: #0f0f23; color: #00d4ff; border-bottom-color: #0f0f23; }}
        .tab:hover {{ color: #e0e0e0; }}
        .tab-content {{ display: none; }}
        .tab-content.active {{ display: block; }}

        /* Filter Bar */
        .filter-bar {{ display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 12px; }}
        .filter-btn {{ padding: 4px 12px; border-radius: 12px; border: 1px solid #2a2a4a; background: transparent; color: #888; cursor: pointer; font-size: 12px; }}
        .filter-btn:hover {{ border-color: #555; color: #e0e0e0; }}
        .filter-btn.active {{ border-color: #00d4ff; color: #00d4ff; background: rgba(0,212,255,0.1); }}

        /* Chart containers */
        .chart-row {{ display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }}
        .chart-box {{ height: 220px; }}

        /* Footer */
        .footer {{ text-align: center; padding: 20px; color: #555; font-size: 12px; }}

        /* Search */
        .search-box {{ padding: 8px 12px; border-radius: 6px; border: 1px solid #2a2a4a; background: #0f0f23; color: #e0e0e0; font-size: 13px; width: 200px; }}
        .search-box:focus {{ outline: none; border-color: #00d4ff; }}

        @media (max-width: 768px) {{
            .chart-row {{ grid-template-columns: 1fr; }}
            .evidence-grid {{ grid-template-columns: 1fr; }}
            .info-grid {{ grid-template-columns: 1fr; }}
            .summary-grid {{ grid-template-columns: repeat(3, 1fr); }}
        }}
    </style>
</head>
<body>
    <div class="nav">
        <a href="#summary">Summary</a>
        <a href="#risk">Risk</a>
        <a href="#distribution">Distribution</a>
        <a href="#files">Files</a>
        <a href="#findings">Findings <span class="badge" style="background:#dc3545;">{critical_count}</span></a>
        <a href="#remediation">Remediation</a>
        <a href="#about">About</a>
    </div>

    <div class="container">
        <!-- Header -->
        <div class="header" id="summary">
            <h1>&#128274; Security Audit Report</h1>
            <div class="meta">
                <span><strong>Project:</strong> {project_name}</span>
                <span><strong>Scan:</strong> {scan_date}</span>
                <span><strong>Tool:</strong> {tool_name} v{tool_version}</span>
                <span><strong>Source:</strong> {project_source}</span>
                <span><strong>Findings:</strong> {total_findings}</span>
            </div>
        </div>

        <!-- Download Bar -->
        <div class="download-bar">
            <span style="color:#888;font-size:13px;padding:8px 0;">Download / 下载:</span>
            <a class="download-btn" href="{report_md_path}" target="_blank">&#128196; Markdown</a>
            <a class="download-btn" href="{report_json_path}" target="_blank">&#128200; JSON</a>
            <span style="color:#888;font-size:12px;padding:8px 0;margin-left:auto;">{findings_count_desc}</span>
        </div>

        <!-- Risk Score -->
        <div class="card" id="risk">
            <h2>&#127919; Risk Assessment / 风险评估</h2>
            <div class="risk-meter">
                <div>
                    <div class="risk-score {risk_class}">{risk_score}</div>
                    <div style="font-size:12px;color:#888;">{risk_label}</div>
                </div>
                <div style="flex:1;">
                    <div class="risk-bar"><div class="risk-bar-fill {risk_class}" style="width:{risk_pct}%;"></div></div>
                    <div style="display:flex;justify-content:space-between;font-size:11px;color:#555;margin-top:4px;">
                        <span>Low / 低</span>
                        <span>Medium / 中</span>
                        <span>High / 高</span>
                        <span>Critical / 严重</span>
                    </div>
                </div>
                <div class="risk-detail">
                    <div>&#128337; Files: {files_scanned}</div>
                    <div>&#128220; Findings: {total_findings}</div>
                    <div>&#9888;&#65039; Critical: {critical_count}</div>
                </div>
            </div>

            <div class="summary-grid">
                <div class="stat-card critical">
                    <div class="stat-number">{critical_count}</div>
                    <div class="stat-label">Critical / 高危</div>
                </div>
                <div class="stat-card high">
                    <div class="stat-number">{high_count}</div>
                    <div class="stat-label">High / 中危</div>
                </div>
                <div class="stat-card medium">
                    <div class="stat-number">{medium_count}</div>
                    <div class="stat-label">Medium / 低危</div>
                </div>
                <div class="stat-card low">
                    <div class="stat-number">{info_count}</div>
                    <div class="stat-label">Info / 信息</div>
                </div>
                <div class="stat-card info">
                    <div class="stat-number">{files_scanned}</div>
                    <div class="stat-label">Files / 文件</div>
                </div>
                <div class="stat-card total">
                    <div class="stat-number">{total_findings}</div>
                    <div class="stat-label">Total / 总计</div>
                </div>
            </div>

            <div class="info-grid" style="margin-top:12px;">
                <div class="info-row"><span class="label">Project</span><span class="value">{project_name}</span></div>
                <div class="info-row"><span class="label">Source</span><span class="value">{project_source}</span></div>
                <div class="info-row"><span class="label">Languages</span><span class="value">{languages}</span></div>
                <div class="info-row"><span class="label">Severity Distribution</span><span class="value">{critical_count}C / {high_count}H / {medium_count}M / {info_count}I</span></div>
                <div class="info-row"><span class="label">Scan Duration</span><span class="value">{scan_duration}s</span></div>
                <div class="info-row"><span class="label">Risk Score</span><span class="value">{risk_score}/100 ({risk_label})</span></div>
            </div>
        </div>

        <!-- Charts -->
        <div class="card" id="distribution">
            <h2>&#128202; Vulnerability Distribution / 漏洞分布</h2>
            <div class="chart-row">
                <div class="chart-box"><canvas id="severityChart"></canvas></div>
                <div class="chart-box"><canvas id="typeChart"></canvas></div>
            </div>
        </div>

        <!-- File Breakdown -->
        <div class="card" id="files">
            <h2>&#128193; File Breakdown / 文件分析</h2>
            {file_breakdown_html}
        </div>

        <!-- All Findings Table -->
        <div class="card">
            <h2>&#128203; Findings Summary / 发现汇总</h2>
            <div style="margin-bottom:12px;display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
                <input class="search-box" id="searchInput" placeholder="Search / 搜索..." onkeyup="filterTable()">
                <button class="filter-btn active" onclick="filterSeverity(this,'all')" id="f-all">All</button>
                <button class="filter-btn" onclick="filterSeverity(this,'critical')" id="f-critical">Critical</button>
                <button class="filter-btn" onclick="filterSeverity(this,'high')" id="f-high">High</button>
                <button class="filter-btn" onclick="filterSeverity(this,'medium')" id="f-medium">Medium</button>
                <button class="filter-btn" onclick="filterSeverity(this,'low')" id="f-low">Low</button>
            </div>
            <div style="overflow-x:auto;">
                <table id="findingsTable">
                    <thead><tr>
                        <th onclick="sortTable(0)">ID</th>
                        <th onclick="sortTable(1)">Severity / 等级</th>
                        <th onclick="sortTable(2)">Type / 类型</th>
                        <th onclick="sortTable(3)">File / 文件</th>
                        <th onclick="sortTable(4)">Line / 行</th>
                        <th onclick="sortTable(5)">CWE</th>
                        <th onclick="sortTable(6)">Status</th>
                    </tr></thead>
                    <tbody id="findingsTableBody">
                        {table_rows_html}
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Detailed Findings -->
        <div class="card" id="findings">
            <h2>&#128270; Detailed Findings / 漏洞详情</h2>
            <div class="tabs">
                <div class="tab active" onclick="switchTab(this,'card')">Card View / 卡片</div>
                <div class="tab" onclick="switchTab(this,'list')">List View / 列表</div>
            </div>
            {findings_html}
        </div>

        <!-- Type Distribution -->
        <div class="card">
            <h2>&#128202; Categories / 漏洞分类</h2>
            <table>
                <tr><th>Type / 漏洞类型</th><th>Count / 数量</th><th>Severity / 等级</th><th>CWE</th></tr>
                {type_dist_html}
            </table>
        </div>

        <!-- Fix Suggestions -->
        <div class="card" id="remediation">
            <h2>&#128295; Remediation / 修复建议</h2>
            {fix_html}
        </div>

        <!-- About -->
        <div class="card" id="about" style="text-align:center;">
            <p style="color:#555;font-size:12px;">
                Generated by {tool_name} v{tool_version}<br>
                Scan Date: {scan_date} &bull; Project: {project_name}
            </p>
        </div>
    </div>

    <script>
        // Severity Chart
        new Chart(document.getElementById('severityChart'), {{
            type: 'doughnut',
            data: {{
                labels: ['Critical / 高危 ({critical_count})', 'High / 中危 ({high_count})', 'Medium / 低危 ({medium_count})', 'Info / 信息 ({info_count})'],
                datasets: [{{
                    data: [{critical_count}, {high_count}, {medium_count}, {info_count}],
                    backgroundColor: ['#dc3545', '#fd7e14', '#ffc107', '#0d6efd'],
                }}]
            }},
            options: {{ responsive: true, maintainAspectRatio: false, plugins: {{ legend: {{ position: 'right', labels: {{ color: '#e0e0e0' }} }} }} }}
        }});

        // Type Chart
        new Chart(document.getElementById('typeChart'), {{
            type: 'bar',
            data: {{
                labels: [{type_labels}],
                datasets: [{{
                    label: 'Count',
                    data: [{type_data}],
                    backgroundColor: [{type_colors}],
                }}]
            }},
            options: {{
                responsive: true, maintainAspectRatio: false,
                plugins: {{ legend: {{ display: false }} }},
                scales: {{ x: {{ ticks: {{ color: '#888' }} }}, y: {{ ticks: {{ color: '#888', stepSize: 1 }} }} }}
            }}
        }});

        // Accordion
        document.querySelectorAll('.finding-header').forEach(h => {{
            h.addEventListener('click', () => {{
                h.nextElementSibling.classList.toggle('open');
            }});
        }});

        // Table filter
        function filterSeverity(btn, sev) {{
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            var rows = document.querySelectorAll('#findingsTableBody tr');
            rows.forEach(r => {{
                if(sev === 'all') {{ r.style.display = ''; }}
                else {{ r.style.display = r.dataset.severity === sev ? '' : 'none'; }}
            }});
        }}

        // Table search
        function filterTable() {{
            var input = document.getElementById('searchInput').value.toLowerCase();
            var rows = document.querySelectorAll('#findingsTableBody tr');
            rows.forEach(r => {{
                r.style.display = r.textContent.toLowerCase().includes(input) ? '' : 'none';
            }});
        }}

        // Table sort
        var sortDir = {{}};
        function sortTable(col) {{
            sortDir[col] = !(sortDir[col] || false);
            var dir = sortDir[col] ? 1 : -1;
            var tbody = document.getElementById('findingsTableBody');
            var rows = Array.from(tbody.querySelectorAll('tr'));
            rows.sort((a,b) => {{
                var va = a.cells[col].textContent.trim(), vb = b.cells[col].textContent.trim();
                return va.localeCompare(vb) * dir;
            }});
            rows.forEach(r => tbody.appendChild(r));
        }}

        // Tab switch
        function switchTab(el, name) {{
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            el.classList.add('active');
        }}
    </script>
</body>
</html>
"""

        # 构建漏洞 HTML 片段（增强版）
        findings_html = ""
        for severity in ["高危", "中危", "低危", "信息"]:
            sev_class = {"高危": "critical", "中危": "high", "低危": "medium", "信息": "low"}[severity]
            sev_label = {"高危": "CRITICAL", "中危": "HIGH", "低危": "MEDIUM", "信息": "INFO"}[severity]
            findings_list = data['severity_groups'].get(severity, [])
            if not findings_list:
                continue

            findings_html += f"<h3 style='margin-top: 20px;'><span class='tag {sev_class}'>{sev_label}</span> ({len(findings_list)} findings)</h3>"

            for f in findings_list:
                # Evidence chain
                poc = f.get('poc', {})
                evidence = poc.get('evidence_chain', {}) if isinstance(poc, dict) else {}
                ver = evidence.get('verification', {}) if evidence else {}
                integrity = evidence.get('evidence_integrity', {}) if evidence else {}

                # Code context
                code_context = ""
                if f.get('context'):
                    code_context = f'''
                    <div class="code-block">
                        {''.join(f'<div><span class="line-num">{l.split(":")[0] if ":" in l else "?"}</span>{l.split(":", 1)[1] if ":" in l else l}</div>' for l in f['context'].split(chr(10)))}
                    </div>'''

                # PoC section
                poc_section = ""
                if isinstance(poc, dict) and poc.get('poc_code'):
                    poc_code = poc['poc_code'][:600]
                    poc_section = f'''
                    <details style="margin-top: 12px;">
                        <summary style="cursor: pointer; color: #fd7e14; font-size: 13px; font-weight: 600;">PoC Exploit Code / 利用代码</summary>
                        <div class="code-block"><pre>{poc_code}</pre></div>
                    </details>'''

                # Evidence section
                evidence_section = ""
                if evidence:
                    call_path = evidence.get('call_path', [])
                    call_path_html = ""
                    if call_path:
                        path_steps = ''.join(f'<div style="font-size: 12px; padding: 2px 0;">[{s.get("step","?")}] Line {s.get("line","?")}: {s.get("code","")}</div>' for s in call_path[-5:])
                        call_path_html = f'''
                        <div style="margin-top: 8px;">
                            <div style="color: #aaa; font-size: 12px;">Call Path / 调用路径:</div>
                            {path_steps}
                            <div style="font-size: 12px; margin-top: 4px;">Source / 输入源: <span style="color: #e0e0e0;">{evidence.get('input_source','N/A')}</span></div>
                            <div style="font-size: 12px;">Sink / 危险函数: <span style="color: #e0e0e0;">{evidence.get('sink_function','N/A')}</span></div>
                        </div>'''

                    integrity_passed = sum(v for v in integrity.values() if isinstance(v, bool))
                    integrity_total = sum(1 for v in integrity.values() if isinstance(v, bool))

                    evidence_section = f'''
                    <details style="margin-top: 12px;">
                        <summary style="cursor: pointer; color: #00d4ff; font-size: 13px; font-weight: 600;">Evidence Chain / 证据链</summary>
                        <div class="evidence">
                            <div class="evidence-grid">
                                <div class="evidence-item"><span class="label">File / 文件</span><br><span class="value">{evidence.get('file_location', {}).get('file','N/A')}</span></div>
                                <div class="evidence-item"><span class="label">Line / 行号</span><br><span class="value">{evidence.get('file_location', {}).get('line','N/A')}</span></div>
                                <div class="evidence-item"><span class="label">Verified / 验证</span><br><span class="value">{'Confirmed' if ver.get('is_real') else 'Unconfirmed'}</span></div>
                                <div class="evidence-item"><span class="label">Integrity / 完整性</span><br><span class="value">{integrity_passed}/{integrity_total}</span></div>
                            </div>
                            {call_path_html}
                            <div style="margin-top: 8px; font-size: 12px; color: #28a745;"><strong>Fix / 修复:</strong> {ver.get('fix_suggestion', f.get('fix_suggestion', 'N/A'))[:200]}</div>
                        </div>
                    </details>'''

                findings_html += f'''
                <div class="finding {sev_class}">
                    <div class="finding-header">
                        <div>
                            <div class="finding-title">{f.get('vuln_name', 'Unknown')}</div>
                            <div class="finding-file">{f.get('file', 'N/A')}:{f.get('line', 'N/A')}</div>
                        </div>
                        <span class="tag {sev_class}">{sev_label}</span>
                    </div>
                    <div style="display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 8px;">
                        <span class="tag cwe">{f.get('cwe', 'N/A')}</span>
                        <span class="tag scope">{f.get('source', 'scanner')}</span>
                    </div>
                    <p style="font-size: 13px; color: #aaa; line-height: 1.5;">{f.get('risk_description', '')}</p>
                    <div style="font-size: 12px; color: #666; margin-top: 4px;"><strong>Match:</strong> <code>{f.get('match', '')[:200]}</code></div>
                    {code_context}
                    {evidence_section}
                    {poc_section}
                </div>'''

        # 漏洞类型分布
        type_dist_html = ""
        for vtype, count in data['summary'].get('by_type', {}).items():
            type_dist_html += f"<tr><td>{vtype}</td><td>{count}</td></tr>"

        # 语言
        lang_str = ', '.join(data['project']['languages'].keys()) if data['project']['languages'] else 'N/A'

        # 修复建议 HTML
        fix_suggestions = {
            "SQL注入": "使用参数化查询或 PreparedStatement，对用户输入进行严格的类型检查和过滤",
            "命令注入": "避免使用 shell=True 或系统命令拼接，使用白名单机制验证用户输入",
            "路径遍历": "对文件路径进行规范化校验，禁止使用 ../ 相对路径",
            "硬编码密钥/凭证": "使用环境变量或密钥管理服务，将密钥移出代码仓库",
            "跨站脚本 (XSS)": "对输出进行 HTML 实体编码，使用 Content-Security-Policy 头",
            "不安全反序列化": "避免反序列化不可信数据，使用安全的数据格式如 JSON",
            "服务端请求伪造 (SSRF)": "对目标 URL 进行白名单校验，禁止访问内网地址",
            "XML外部实体注入 (XXE)": "禁用 XML 解析器的外部实体加载功能",
            "跨站请求伪造 (CSRF)": "使用 CSRF Token，验证请求来源 Referer",
            "开放重定向": "对重定向 URL 进行白名单校验，禁止外部跳转",
            "LDAP注入": "对 LDAP 查询参数进行转义和过滤",
            "NoSQL注入": "使用参数化查询，避免拼接查询语句",
            "服务端模板注入 (SSTI)": "避免将用户输入直接传入模板渲染函数",
            "不安全文件上传": "限制上传文件类型，对上传文件进行安全扫描",
            "JWT安全漏洞": "禁用 'none' 算法，使用强密钥签名，验证签名和过期时间",
            "日志伪造": "对日志输入进行换行符过滤和转义",
            "CRLF注入/HTTP响应拆分": "对 HTTP 头部参数进行换行符过滤",
        }
        fix_html = ""
        for vuln_name in data['summary'].get('by_type', {}):
            suggestion = fix_suggestions.get(vuln_name, "根据具体漏洞类型采取相应的安全修复措施")
            fix_html += f'<div class="evidence" style="margin-bottom: 8px;"><strong>{vuln_name}</strong><br><span style="color: #aaa; font-size: 13px;">{suggestion}</span></div>\n'

        # 漏洞类型分布（含严重等级）
        severity_map = {}
        for f in data['findings']:
            sev = f.get("severity", "信息")
            name = f.get("vuln_name", "未知")
            if name not in severity_map:
                severity_map[name] = sev

        type_dist_html = ""
        for vtype, count in data['summary'].get('by_type', {}).items():
            sev = severity_map.get(vtype, "信息")
            cls = {'高危': 'critical', '中危': 'high', '低危': 'medium', '信息': 'low'}.get(sev, 'low')
            type_dist_html += f'<tr><td>{vtype}</td><td>{count}</td><td><span class="tag {cls}">{sev}</span></td></tr>'

        # 风险评分计算
        c = data['summary']['by_severity'].get('高危', 0)
        h = data['summary']['by_severity'].get('中危', 0)
        m = data['summary']['by_severity'].get('低危', 0)
        i = data['summary']['by_severity'].get('信息', 0)
        risk_score = min(100, c * 25 + h * 10 + m * 5)
        if risk_score >= 70:
            risk_class, risk_label = 'critical', 'CRITICAL / 严重'
        elif risk_score >= 40:
            risk_class, risk_label = 'high', 'HIGH / 高危'
        elif risk_score >= 15:
            risk_class, risk_label = 'medium', 'MEDIUM / 中危'
        else:
            risk_class, risk_label = 'low', 'LOW / 低危'

        # 表格行
        table_rows_html = ""
        for sev_order in ["高危", "中危", "低危", "信息"]:
            sev_map = {"高危": "critical", "中危": "high", "低危": "medium", "信息": "low"}
            for f in data['severity_groups'].get(sev_order, []):
                sev_cls = sev_map.get(sev_order, "low")
                table_rows_html += f'''
                <tr data-severity="{sev_cls}">
                    <td style="font-size:11px;color:#666;">{f.get('id','')}</td>
                    <td><span class="tag {sev_cls}">{sev_order}</span></td>
                    <td>{f.get('vuln_name','')}</td>
                    <td style="font-family:monospace;font-size:12px;">{f.get('file','')}</td>
                    <td>{f.get('line','')}</td>
                    <td><span class="tag cwe">{f.get('cwe','')}</span></td>
                    <td><span class="status {'ok' if f.get('is_real',True) else 'warn'}">{'Confirmed' if f.get('is_real',True) else 'Pending'}</span></td>
                </tr>'''

        # 类型图表数据
        type_counts = data['summary'].get('by_type', {})
        sorted_types = sorted(type_counts.items(), key=lambda x: x[1], reverse=True)
        type_labels = ','.join(f"'{t[0][:12]}'" for t in sorted_types[:10])
        type_data = ','.join(str(t[1]) for t in sorted_types[:10])
        type_colors = ','.join(["'#dc3545'","'#fd7e14'","'#ffc107'","'#28a745'","'#0d6efd'","'#6f42c1'","'#20c997'","'#e83e8c'","'#17a2b8'","'#6c757d'"][:len(sorted_types[:10])])

        # 文件分布
        file_counts = data['summary'].get('by_file', {})
        file_breakdown_html = ""
        if file_counts:
            file_breakdown_html = '<table><tr><th>File / 文件</th><th>Findings / 发现数</th><th>Files / 占比</th></tr>'
            total_files = data['summary']['scan_stats'].get('files_scanned', 1) or 1
            for fname, fcount in list(file_counts.items())[:15]:
                pct = fcount / max(data['summary']['total_findings'], 1) * 100
                file_breakdown_html += f'<tr><td style="font-family:monospace;font-size:12px;">{fname}</td><td>{fcount}</td><td>{pct:.0f}%</td></tr>'
            file_breakdown_html += '</table>'
        else:
            file_breakdown_html = '<p style="color:#555;font-size:13px;">No file-specific data available.</p>'

        # 报告路径
        base_dir = os.path.dirname(output_path)
        base_name = os.path.basename(output_path).replace('.html', '')
        report_md_path = f"{base_name}.md"
        report_json_path = f"{base_name}.json"
        findings_count_desc = f"{data['summary']['total_findings']} findings ({c} critical, {h} high, {m} medium, {i} info)"
        scan_duration = data['summary']['scan_stats'].get('elapsed', 0) if data['summary']['scan_stats'] else 0

        # 填充模板
        html = html.format(
            project_name=data['project']['name'],
            project_source=data['project'].get('source', 'N/A'),
            scan_date=data['metadata']['scan_date'],
            tool_name=data['metadata']['tool'],
            tool_version=data['metadata']['version'],
            total_findings=data['summary']['total_findings'],
            critical_count=c, high_count=h, medium_count=m, info_count=i,
            files_scanned=data['summary']['scan_stats'].get('files_scanned', 0) if data['summary']['scan_stats'] else 0,
            languages=lang_str,
            findings_html=findings_html,
            type_dist_html=type_dist_html,
            fix_html=fix_html,
            risk_score=risk_score, risk_class=risk_class,
            risk_label=risk_label, risk_pct=risk_score,
            report_md_path=report_md_path, report_json_path=report_json_path,
            findings_count_desc=findings_count_desc,
            table_rows_html=table_rows_html,
            type_labels=type_labels, type_data=type_data, type_colors=type_colors,
            file_breakdown_html=file_breakdown_html,
            scan_duration=scan_duration,
        )

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)
