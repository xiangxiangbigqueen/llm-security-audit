"""报告生成模块测试"""
import os
import sys
import tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from report.generator import ReportGenerator


def test_report_generation():
    """测试报告生成"""
    generator = ReportGenerator()

    # 模拟报告数据
    report_data = {
        "executive_summary": "本次安全审计发现3个安全漏洞，其中1个严重、1个高危、1个中危。",
        "risk_score": 75,
        "vulnerabilities_summary": {
            "critical": 1,
            "high": 1,
            "medium": 1,
            "low": 0,
        },
        "project_info": {
            "name": "test_project",
            "languages": {"C": 60.0, "PHP": 40.0},
            "file_count": 4,
        },
        "vulnerabilities": [
            {
                "vulnerability_id": "VULN-TEST0001",
                "vulnerability_type": "Buffer Overflow",
                "severity": "critical",
                "file_path": "src/main.c",
                "line_number": 42,
                "code_snippet": "gets(buffer);",
                "data_flow": "stdin -> gets() -> buffer",
                "reasoning": "gets()函数无边界检查，用户输入可溢出栈缓冲区",
                "poc_code": "python -c 'print(\"A\"*200)' | ./vulnerable_app",
                "impact_analysis": "可导致任意代码执行",
            },
            {
                "vulnerability_id": "VULN-TEST0002",
                "vulnerability_type": "SQL Injection",
                "severity": "high",
                "file_path": "src/login.php",
                "line_number": 10,
                "code_snippet": "$query = \"SELECT * FROM users WHERE username='\" . $username . \"'\";",
                "data_flow": "$_GET['username'] -> $query -> mysqli_query()",
                "reasoning": "用户输入直接拼接到SQL语句中",
                "poc_code": "curl 'http://target/login.php?username=admin%27%20OR%201=1--'",
                "impact_analysis": "可绕过认证、读取/修改数据库",
            },
        ],
    }

    # 生成HTML报告
    html_path = os.path.join(tempfile.gettempdir(), "test_report.html")
    result = generator.generate_html(report_data, html_path)
    assert os.path.exists(result), f"HTML报告文件应存在: {result}"
    print(f"✓ HTML报告生成成功: {result}")

    # 生成Markdown报告
    md_path = os.path.join(tempfile.gettempdir(), "test_report.md")
    result = generator.generate_markdown(report_data, md_path)
    assert os.path.exists(result), f"Markdown报告文件应存在: {result}"
    print(f"✓ Markdown报告生成成功: {result}")

    # 检查内容
    with open(html_path, 'r') as f:
        html = f.read()
        assert "VULN-TEST0001" in html
        assert "Buffer Overflow" in html

    with open(md_path, 'r') as f:
        md = f.read()
        assert "SQL Injection" in md
        assert "test_project" in md

    print("✓ 报告内容验证通过")


if __name__ == "__main__":
    test_report_generation()
    print("\n报告测试全部通过!")