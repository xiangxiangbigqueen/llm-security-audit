"""报告生成器"""
import html
import json
import os
import time
from pathlib import Path
from typing import Dict, List
from datetime import datetime

from config.full_settings import REPORT_OUTPUT_DIR


def _escape(v):
    """递归 HTML 转义，防止报告中嵌入的漏洞代码被浏览器执行"""
    if isinstance(v, str):
        return html.escape(v)
    if isinstance(v, dict):
        return {k: _escape(v) for k, v in v.items()}
    if isinstance(v, list):
        return [_escape(i) for i in v]
    return v


class ReportGenerator:
    """生成HTML和Markdown格式的审计报告"""

    def __init__(self):
        self.output_dir = REPORT_OUTPUT_DIR

    def generate_html(self, report_data: Dict, output_path: str = None) -> str:
        """生成HTML格式报告"""
        if output_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            project_name = report_data.get("project_info", {}).get("name", "unknown")
            output_path = str(self.output_dir / f"report_{project_name}_{timestamp}.html")

        html_content = self._render_html(report_data)

        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)

        return output_path

    def generate_markdown(self, report_data: Dict, output_path: str = None) -> str:
        """生成Markdown格式报告"""
        if output_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            project_name = report_data.get("project_info", {}).get("name", "unknown")
            output_path = str(self.output_dir / f"report_{project_name}_{timestamp}.md")

        md_content = self._render_markdown(report_data)

        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(md_content)

        return output_path

    def _render_html(self, data: Dict) -> str:
        """渲染HTML报告"""
        vulns = _escape(data.get("vulnerabilities", []))
        summary = data.get("vulnerabilities_summary", {})
        project = data.get("project_info", {})

        vuln_rows = ""
        for v in vulns:
            severity_color = {"critical": "#dc3545", "high": "#fd7e14", "medium": "#ffc107", "low": "#28a745"}.get(v.get("severity", ""), "#6c757d")
            poc_section = f"<pre><code>{v.get('poc_code', 'N/A')[:500]}</code></pre>" if v.get('poc_code') else "<em>无</em>"
            vuln_rows += f"""
            <div class="vuln-card" style="border-left: 4px solid {severity_color};">
                <h3>{v.get('vulnerability_id', 'N/A')} - {v.get('vulnerability_type', 'Unknown')}</h3>
                <span class="severity" style="background:{severity_color};color:white;padding:2px 8px;border-radius:3px;">{v.get('severity', 'N/A').upper()}</span>
                <p><strong>文件:</strong> {v.get('file_path', 'N/A')}:{v.get('line_number', 0)}</p>
                <p><strong>代码片段:</strong></p>
                <pre><code>{v.get('code_snippet', 'N/A')}</code></pre>
                <p><strong>数据流:</strong> {v.get('data_flow', 'N/A')}</p>
                <p><strong>判断理由:</strong> {v.get('reasoning', 'N/A')}</p>
                <p><strong>影响分析:</strong> {v.get('impact_analysis', 'N/A')}</p>
                <details><summary>PoC代码</summary>{poc_section}</details>
            </div>"""

        return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>CodeSentinel 安全审计报告 - {project.get('name', 'Unknown')}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #1a1a2e; border-bottom: 3px solid #e94560; padding-bottom: 10px; }}
        h2 {{ color: #16213e; margin-top: 30px; }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin: 20px 0; }}
        .summary-card {{ padding: 20px; border-radius: 8px; text-align: center; color: white; }}
        .summary-card h3 {{ margin: 0; font-size: 2em; }}
        .summary-card p {{ margin: 5px 0 0; }}
        .vuln-card {{ background: #f8f9fa; padding: 20px; margin: 15px 0; border-radius: 5px; }}
        pre {{ background: #2d2d2d; color: #f8f8f2; padding: 15px; border-radius: 5px; overflow-x: auto; }}
        details {{ margin-top: 10px; }}
        summary {{ cursor: pointer; color: #e94560; font-weight: bold; }}
    </style>
</head>
<body>
<div class="container">
    <h1>CodeSentinel 安全审计报告</h1>
    <p><strong>项目:</strong> {project.get('name', 'N/A')} | <strong>语言:</strong> {json.dumps(project.get('languages', {}), ensure_ascii=False)} | <strong>时间:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>

    <h2>执行摘要</h2>
    <p>{data.get('executive_summary', '安全审计已完成。')}</p>
    <p><strong>风险评分:</strong> {data.get('risk_score', 0)}/100</p>

    <div class="summary-grid">
        <div class="summary-card" style="background:#dc3545;"><h3>{summary.get('critical', 0)}</h3><p>严重</p></div>
        <div class="summary-card" style="background:#fd7e14;"><h3>{summary.get('high', 0)}</h3><p>高危</p></div>
        <div class="summary-card" style="background:#ffc107;color:#333;"><h3>{summary.get('medium', 0)}</h3><p>中危</p></div>
        <div class="summary-card" style="background:#28a745;"><h3>{summary.get('low', 0)}</h3><p>低危</p></div>
    </div>

    <h2>漏洞详情</h2>
    {vuln_rows if vuln_rows else '<p>未发现确认的安全漏洞。</p>'}

    <hr>
    <p style="color:#666;font-size:0.9em;">报告由 CodeSentinel 自动生成 | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
</div>
</body>
</html>"""

    def _render_markdown(self, data: Dict) -> str:
        """渲染Markdown报告"""
        vulns = data.get("vulnerabilities", [])
        summary = data.get("vulnerabilities_summary", {})
        project = data.get("project_info", {})

        md = f"""# CodeSentinel 安全审计报告

## 项目信息
- **项目名称:** {project.get('name', 'N/A')}
- **编程语言:** {json.dumps(project.get('languages', {}), ensure_ascii=False)}
- **文件数量:** {project.get('file_count', 0)}
- **审计时间:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## 执行摘要

{data.get('executive_summary', '安全审计已完成。')}

**风险评分:** {data.get('risk_score', 0)}/100

## 漏洞统计

| 严重等级 | 数量 |
|---------|------|
| Critical | {summary.get('critical', 0)} |
| High | {summary.get('high', 0)} |
| Medium | {summary.get('medium', 0)} |
| Low | {summary.get('low', 0)} |
| **总计** | **{sum(summary.values())}** |

## 漏洞详情

"""
        for v in vulns:
            md += f"""### {v.get('vulnerability_id', 'N/A')} - {v.get('vulnerability_type', 'Unknown')}

- **严重等级:** {v.get('severity', 'N/A').upper()}
- **文件位置:** `{v.get('file_path', 'N/A')}:{v.get('line_number', 0)}`
- **数据流:** {v.get('data_flow', 'N/A')}
- **判断理由:** {v.get('reasoning', 'N/A')}

**代码片段:**
```
{v.get('code_snippet', 'N/A')}
```

**PoC代码:**
```python
{v.get('poc_code', '# 无PoC')}
```

---

"""
        md += "\n\n*报告由 CodeSentinel 自动生成*\n"
        return md