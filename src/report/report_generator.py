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
from typing import Optional
from collections import Counter


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
        html = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>安全审计报告 - {project_name}</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, 'Microsoft YaHei', 'Segoe UI', sans-serif; background: #0f0f23; color: #e0e0e0; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}

        /* Header */
        .header {{ background: linear-gradient(135deg, #1a1a2e, #16213e); border: 1px solid #2a2a4a; border-radius: 16px; padding: 30px 40px; margin-bottom: 24px; }}
        .header h1 {{ font-size: 28px; background: linear-gradient(135deg, #00d4ff, #7b2ff7); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }}
        .header .meta {{ margin-top: 12px; font-size: 13px; color: #888; }}
        .header .meta span {{ display: inline-block; margin-right: 24px; }}

        /* Cards */
        .card {{ background: #1a1a3e; border: 1px solid #2a2a4a; border-radius: 12px; padding: 24px; margin-bottom: 16px; }}
        .card h2 {{ font-size: 18px; margin-bottom: 16px; padding-bottom: 8px; border-bottom: 1px solid #2a2a4a; color: #00d4ff; }}

        /* Summary stats */
        .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 12px; }}
        .stat-card {{ text-align: center; padding: 16px; border-radius: 10px; }}
        .stat-card.critical {{ background: rgba(220,53,69,0.15); border: 1px solid rgba(220,53,69,0.3); }}
        .stat-card.high {{ background: rgba(253,126,20,0.15); border: 1px solid rgba(253,126,20,0.3); }}
        .stat-card.medium {{ background: rgba(255,193,7,0.15); border: 1px solid rgba(255,193,7,0.3); }}
        .stat-card.low {{ background: rgba(40,167,69,0.15); border: 1px solid rgba(40,167,69,0.3); }}
        .stat-card.info {{ background: rgba(13,110,253,0.15); border: 1px solid rgba(13,110,253,0.3); }}
        .stat-number {{ font-size: 36px; font-weight: bold; }}
        .stat-card.critical .stat-number {{ color: #dc3545; }}
        .stat-card.high .stat-number {{ color: #fd7e14; }}
        .stat-card.medium .stat-number {{ color: #ffc107; }}
        .stat-card.low .stat-number {{ color: #28a745; }}
        .stat-card.info .stat-number {{ color: #0d6efd; }}
        .stat-label {{ font-size: 12px; color: #888; margin-top: 4px; }}

        /* Project info table */
        .info-table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
        .info-table td {{ padding: 6px 12px; border-bottom: 1px solid #2a2a4a; }}
        .info-table td:first-child {{ color: #888; width: 120px; }}

        /* Findings */
        .finding {{ border: 1px solid #2a2a4a; border-left: 4px solid #555; padding: 20px; margin-bottom: 16px; border-radius: 0 10px 10px 0; background: #0f0f23; }}
        .finding.critical {{ border-left-color: #dc3545; }}
        .finding.high {{ border-left-color: #fd7e14; }}
        .finding.medium {{ border-left-color: #ffc107; }}
        .finding.low {{ border-left-color: #28a745; }}
        .finding-header {{ display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 12px; }}
        .finding-title {{ font-size: 16px; font-weight: 600; }}
        .finding-file {{ font-family: 'Courier New', monospace; font-size: 12px; color: #888; margin-top: 4px; }}

        /* Tags */
        .tag {{ display: inline-block; padding: 3px 10px; border-radius: 4px; font-size: 11px; font-weight: 600; }}
        .tag.critical {{ background: #dc3545; color: white; }}
        .tag.high {{ background: #fd7e14; color: white; }}
        .tag.medium {{ background: #ffc107; color: #333; }}
        .tag.low {{ background: #28a745; color: white; }}
        .tag.cwe {{ background: #6f42c1; color: white; }}
        .tag.scope {{ background: #2a2a4a; color: #aaa; }}

        /* Code */
        pre, code {{ font-family: 'Courier New', monospace; }}
        .code-block {{ background: #0a0a1a; border: 1px solid #2a2a4a; border-radius: 8px; padding: 12px; overflow-x: auto; font-size: 12px; margin-top: 8px; }}
        .code-block .line-num {{ color: #555; user-select: none; margin-right: 12px; }}
        .code-block .highlight {{ background: rgba(220,53,69,0.2); border-left: 3px solid #dc3545; padding-left: 8px; }}

        /* Evidence Chain */
        .evidence {{ background: #0a0a1a; border: 1px solid #2a2a4a; border-radius: 8px; padding: 16px; margin-top: 12px; }}
        .evidence h4 {{ color: #00d4ff; font-size: 14px; margin-bottom: 8px; }}
        .evidence-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }}
        .evidence-item {{ padding: 8px; border-radius: 6px; background: #1a1a3e; font-size: 12px; }}
        .evidence-item .label {{ color: #888; }}
        .evidence-item .value {{ color: #e0e0e0; }}

        /* Status indicators */
        .status {{ display: inline-flex; align-items: center; gap: 4px; padding: 2px 8px; border-radius: 4px; font-size: 11px; }}
        .status.ok {{ background: rgba(40,167,69,0.2); color: #28a745; }}
        .status.warn {{ background: rgba(255,193,7,0.2); color: #ffc107; }}

        /* Charts */
        .chart-container {{ height: 250px; margin: 16px 0; }}

        /* Tables */
        table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
        th, td {{ padding: 8px 12px; text-align: left; border-bottom: 1px solid #2a2a4a; }}
        th {{ color: #888; font-weight: 600; font-size: 12px; text-transform: uppercase; }}
        tr:hover {{ background: rgba(255,255,255,0.02); }}

        /* Footer */
        .footer {{ text-align: center; padding: 20px; color: #555; font-size: 12px; }}

        /* Tabs */
        .tabs {{ display: flex; gap: 4px; margin-bottom: 16px; }}
        .tab {{ padding: 8px 16px; border-radius: 6px 6px 0 0; background: #1a1a3e; border: 1px solid #2a2a4a; border-bottom: none; cursor: pointer; font-size: 13px; color: #888; }}
        .tab.active {{ background: #0f0f23; color: #00d4ff; border-color: #00d4ff; }}
        .tab:hover {{ color: #e0e0e0; }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <h1>Security Audit Report</h1>
            <div class="meta">
                <span>Project: {project_name}</span>
                <span>Scan: {scan_date}</span>
                <span>Tool: {tool_name} v{tool_version}</span>
            </div>
        </div>

        <!-- Summary Stats -->
        <div class="card">
            <h2>Summary / 扫描摘要</h2>
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
                    <div class="stat-number">{total_findings}</div>
                    <div class="stat-label">Total / 总计</div>
                </div>
                <div class="stat-card info">
                    <div class="stat-number">{files_scanned}</div>
                    <div class="stat-label">Files / 文件数</div>
                </div>
            </div>
            <table class="info-table" style="margin-top: 12px;">
                <tr><td>Project</td><td>{project_name}</td><td>Language</td><td>{languages}</td></tr>
                <tr><td>Source</td><td>{project_source}</td><td>Findings</td><td>{total_findings} ({critical_count} critical)</td></tr>
            </table>
        </div>

        <!-- Charts -->
        <div class="card">
            <h2>Distribution / 漏洞分布</h2>
            <div class="chart-container">
                <canvas id="severityChart"></canvas>
            </div>
        </div>

        <!-- Findings -->
        <div class="card">
            <h2>Findings / 漏洞详情</h2>
            {findings_html}
        </div>

        <!-- Type Distribution Table -->
        <div class="card">
            <h2>Categories / 漏洞分类</h2>
            <table>
                <tr><th>Type / 漏洞类型</th><th>Count / 数量</th><th>Severity / 等级</th></tr>
                {type_dist_html}
            </table>
        </div>

        <!-- Fix Suggestions -->
        <div class="card">
            <h2>Remediation / 修复建议</h2>
            {fix_html}
        </div>

        <div class="footer">
            Generated by {tool_name} v{tool_version} | {scan_date}
        </div>
    </div>

    <script>
        const ctx = document.getElementById('severityChart').getContext('2d');
        new Chart(ctx, {{
            type: 'doughnut',
            data: {{
                labels: ['Critical / 高危 ({critical_count})', 'High / 中危 ({high_count})', 'Medium / 低危 ({medium_count})', 'Info / 信息 ({info_count})'],
                datasets: [{{
                    data: [{critical_count}, {high_count}, {medium_count}, {info_count}],
                    backgroundColor: ['#dc3545', '#fd7e14', '#ffc107', '#0d6efd'],
                    borderColor: ['#dc3545', '#fd7e14', '#ffc107', '#0d6efd'],
                    borderWidth: 2
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{ position: 'right', labels: {{ color: '#e0e0e0', padding: 16 }} }},
                    tooltip: {{ callbacks: {{ label: function(ctx) {{ return ctx.label + ': ' + ctx.parsed; }} }} }}
                }}
            }}
        }});
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

        # 填充模板
        html = html.format(
            project_name=data['project']['name'],
            project_source=data['project'].get('source', 'N/A'),
            scan_date=data['metadata']['scan_date'],
            tool_name=data['metadata']['tool'],
            tool_version=data['metadata']['version'],
            total_findings=data['summary']['total_findings'],
            critical_count=data['summary']['by_severity'].get('高危', 0),
            high_count=data['summary']['by_severity'].get('中危', 0),
            medium_count=data['summary']['by_severity'].get('低危', 0),
            info_count=data['summary']['by_severity'].get('信息', 0),
            files_scanned=data['summary']['scan_stats'].get('files_scanned', 0) if data['summary']['scan_stats'] else 0,
            languages=lang_str,
            findings_html=findings_html,
            type_dist_html=type_dist_html,
            fix_html=fix_html,
        )

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)
