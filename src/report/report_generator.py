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
        """生成 HTML 格式报告"""
        html = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>安全审计报告 - {project_name}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, 'Microsoft YaHei', sans-serif; background: #f5f5f5; color: #333; }}
        .container {{ max-width: 1000px; margin: 0 auto; padding: 20px; }}
        .header {{ background: linear-gradient(135deg, #1a1a2e, #16213e); color: white; padding: 40px; border-radius: 12px; margin-bottom: 24px; }}
        .header h1 {{ font-size: 28px; }}
        .header .meta {{ margin-top: 12px; opacity: 0.8; font-size: 14px; }}
        .card {{ background: white; border-radius: 12px; padding: 24px; margin-bottom: 16px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }}
        .card h2 {{ font-size: 20px; margin-bottom: 16px; border-bottom: 2px solid #eee; padding-bottom: 8px; }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; }}
        .stat-card {{ text-align: center; padding: 16px; border-radius: 8px; }}
        .stat-card.critical {{ background: #fff0f0; border: 1px solid #ffcccc; }}
        .stat-card.high {{ background: #fff5f0; border: 1px solid #ffd4cc; }}
        .stat-card.medium {{ background: #fffcf0; border: 1px solid #ffe8cc; }}
        .stat-card.low {{ background: #f0fff4; border: 1px solid #ccffd8; }}
        .stat-number {{ font-size: 32px; font-weight: bold; }}
        .stat-label {{ font-size: 13px; color: #666; margin-top: 4px; }}
        .finding {{ border-left: 4px solid #ccc; padding: 16px; margin-bottom: 12px; border-radius: 0 8px 8px 0; background: #fafafa; }}
        .finding.critical {{ border-color: #dc3545; }}
        .finding.high {{ border-color: #fd7e14; }}
        .finding.medium {{ border-color: #ffc107; }}
        .finding.low {{ border-color: #28a745; }}
        .finding-header {{ display: flex; justify-content: space-between; align-items: start; }}
        .finding-file {{ font-family: monospace; background: #eee; padding: 2px 8px; border-radius: 4px; font-size: 13px; }}
        .tag {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 12px; color: white; }}
        .tag.critical {{ background: #dc3545; }}
        .tag.high {{ background: #fd7e14; }}
        .tag.medium {{ background: #ffc107; color: #333; }}
        .tag.low {{ background: #28a745; }}
        pre {{ background: #f0f0f0; padding: 12px; border-radius: 8px; overflow-x: auto; font-size: 13px; margin-top: 8px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 8px; }}
        th, td {{ padding: 8px 12px; text-align: left; border-bottom: 1px solid #eee; }}
        th {{ font-weight: 600; color: #555; font-size: 13px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 安全审计报告</h1>
            <div class="meta">
                <div>项目: {project_name}</div>
                <div>扫描时间: {scan_date}</div>
                <div>生成工具: {tool_name} v{tool_version}</div>
            </div>
        </div>

        <div class="card">
            <h2>📊 扫描摘要</h2>
            <div class="summary-grid">
                <div class="stat-card critical">
                    <div class="stat-number">{critical_count}</div>
                    <div class="stat-label">🔴 高危</div>
                </div>
                <div class="stat-card high">
                    <div class="stat-number">{high_count}</div>
                    <div class="stat-label">🟡 中危</div>
                </div>
                <div class="stat-card medium">
                    <div class="stat-number">{medium_count}</div>
                    <div class="stat-label">🟢 低危</div>
                </div>
                <div class="stat-card low">
                    <div class="stat-number">{info_count}</div>
                    <div class="stat-label">🔵 信息</div>
                </div>
            </div>
            <div style="margin-top: 16px;">
                <table>
                    <tr><td>总发现数</td><td>{total_findings}</td></tr>
                    <tr><td>扫描文件数</td><td>{files_scanned}</td></tr>
                    <tr><td>编程语言</td><td>{languages}</td></tr>
                </table>
            </div>
        </div>

        <div class="card">
            <h2>🐛 漏洞详情</h2>
            {findings_html}
        </div>

        <div class="card">
            <h2>📈 漏洞类型分布</h2>
            <table>
                <tr><th>漏洞类型</th><th>数量</th></tr>
                {type_dist_html}
            </table>
        </div>

        <div class="card" style="text-align: center; color: #888; font-size: 13px;">
            报告由 {tool_name} 自动生成
        </div>
    </div>
</body>
</html>
"""

        # 构建漏洞 HTML 片段
        findings_html = ""
        for severity in ["高危", "中危", "低危", "信息"]:
            sev_class = {"高危": "critical", "中危": "high", "低危": "medium", "信息": "low"}[severity]
            findings_list = data['severity_groups'].get(severity, [])
            if not findings_list:
                continue

            emoji = {"高危": "🔴", "中危": "🟡", "低危": "🟢", "信息": "🔵"}[severity]
            findings_html += f"<h3>{emoji} {severity} ({len(findings_list)} 个)</h3>"

            for f in findings_list:
                findings_html += f'''
                <div class="finding {sev_class}">
                    <div class="finding-header">
                        <div>
                            <strong>{f['vuln_name']}</strong>
                            <span class="finding-file">{f['file']}:{f['line']}</span>
                        </div>
                        <span class="tag {sev_class}">{severity}</span>
                    </div>
                    <p style="margin-top: 8px; font-size: 14px;">{f.get('risk_description', '')}</p>
                    <p style="margin-top: 4px; font-size: 13px; color: #666;">
                        <strong>CWE:</strong> {f.get('cwe', 'N/A')} |
                        <strong>匹配:</strong> <code>{f.get('match', '')[:100]}</code>
                    </p>
                </div>'''

        # 漏洞类型分布
        type_dist_html = ""
        for vtype, count in data['summary'].get('by_type', {}).items():
            type_dist_html += f"<tr><td>{vtype}</td><td>{count}</td></tr>"

        # 语言
        lang_str = ', '.join(data['project']['languages'].keys()) if data['project']['languages'] else 'N/A'

        # 填充模板
        html = html.format(
            project_name=data['project']['name'],
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
        )

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)
