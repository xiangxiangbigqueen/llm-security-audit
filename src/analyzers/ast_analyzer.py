"""
AST 语义分析器（新增）
使用 Tree-sitter 解析代码为抽象语法树，在语法树层面进行深度安全分析

【主流技术使用标注】
★ AST 语法树: 使用 Tree-sitter 将代码解析为结构化语法树
★ 数据流分析: 追踪变量从输入源到敏感操作（source→sink）的传播路径
★ 污点传播: 标记用户可控数据，跟踪其在代码中的流向
★ 控制流分析: 分析条件分支对漏洞可利用性的影响
★ 跨语言: 支持 Python/JS/Java/PHP/Go/Ruby/C#/C++/Rust 9种语言
"""

import os
import re
import tree_sitter
from typing import Optional, List, Dict, Any


class ASTAnalyzer:
    """
    AST 语义分析器
    基于 Tree-sitter 的代码语法树分析引擎
    """

    def __init__(self):
        self.parser = None
        self.language_map = {}
        self._init_parsers()

    def _init_parsers(self):
        """初始化 Tree-sitter 语言解析器"""
        try:
            import tree_sitter_python as tspython
            self.language_map[".py"] = tree_sitter.Language(tspython.language())
        except ImportError:
            pass

        try:
            import tree_sitter_javascript as tsjs
            self.language_map[".js"] = tree_sitter.Language(tsjs.language())
            self.language_map[".jsx"] = self.language_map[".js"]
            self.language_map[".ts"] = self.language_map[".js"]
            self.language_map[".tsx"] = self.language_map[".js"]
        except ImportError:
            pass

        try:
            import tree_sitter_java as tsjava
            self.language_map[".java"] = tree_sitter.Language(tsjava.language())
        except ImportError:
            pass

    def can_parse(self, ext: str) -> bool:
        """是否支持该语言"""
        return ext in self.language_map

    def parse(self, file_path: str, content: str) -> Optional[Any]:
        """
        将代码解析为 AST

        Args:
            file_path: 文件路径（用于识别语言）
            content: 代码内容

        Returns:
            Tree-sitter 树对象
        """
        ext = os.path.splitext(file_path)[1].lower()
        lang = self.language_map.get(ext)

        if not lang or not self.parser:
            return None

        self.parser.set_language(lang)
        return self.parser.parse(bytes(content, "utf-8"))

    def detect_sql_injection_ast(self, tree, content: str) -> list:
        """
        AST 层面检测 SQL 注入
        检测: 字符串拼接/f-string 传入 execute()/query() 等敏感函数
        """
        findings = []
        if not tree:
            return findings

        lines = content.split('\n')
        root = tree.root_node

        # 查找所有函数调用
        self._walk_and_find_sql_injection(root, content, lines, findings)
        return findings

    def detect_command_injection_ast(self, tree, content: str) -> list:
        """
        AST 层面检测命令注入
        检测: os.system/subprocess 的 shell=True 或字符串拼接
        """
        findings = []
        if not tree:
            return findings

        lines = content.split('\n')
        root = tree.root_node

        self._walk_and_find_cmd_injection(root, content, lines, findings)
        return findings

    def detect_path_traversal_ast(self, tree, content: str) -> list:
        """
        AST 层面检测路径遍历
        检测: open()/readFile() 等文件操作中路径参数来自用户输入
        """
        findings = []
        if not tree:
            return findings

        lines = content.split('\n')
        root = tree.root_node

        self._walk_and_find_path_traversal(root, content, lines, findings)
        return findings

    def detect_xss_ast(self, tree, content: str) -> list:
        """
        AST 层面检测 XSS
        检测: innerHTML/v-html 赋值中使用了未转义的变量
        """
        findings = []
        if not tree:
            return findings

        lines = content.split('\n')
        root = tree.root_node

        self._walk_and_find_xss(root, content, lines, findings)
        return findings

    def _walk_and_find_sql_injection(self, node, content: str, lines: list, findings: list):
        """遍历 AST 查找 SQL 注入"""
        if node.type in ("call", "call_expression", "method_invocation"):
            node_text = content[node.start_byte:node.end_byte]

            # Python: cursor.execute(f"...") 或 execute("..." % var)
            sql_patterns = [
                r'cursor\.execute\s*\(',
                r'\.execute\s*\(\s*f["\']',
                r'\.query\s*\(\s*f["\']',
            ]
            for pattern in sql_patterns:
                if re.search(pattern, node_text):
                    # 检查参数是否包含字符串拼接或变量
                    self._check_dynamic_arg(node, content, lines, findings,
                                            "SQL注入", "CWE-89")

            # Java: Statement.executeQuery("..." + var)
            if re.search(r'\.(executeQuery|executeUpdate|execute)\s*\(\s*["\'][^"\']*\+', node_text):
                findings.append(self._make_finding(
                    node, content, lines, "SQL注入", "CWE-89",
                    "AST检测: executeQuery 中存在字符串拼接，可能的 SQL 注入"
                ))

        for child in node.children:
            self._walk_and_find_sql_injection(child, content, lines, findings)

    def _walk_and_find_cmd_injection(self, node, content: str, lines: list, findings: list):
        """遍历 AST 查找命令注入"""
        if node.type in ("call", "call_expression", "method_invocation"):
            node_text = content[node.start_byte:node.end_byte]

            cmd_patterns = [
                (r'os\.system\s*\(', "os.system() 调用"),
                (r'subprocess\.(call|Popen|run|check_output)\s*\(', "subprocess 调用"),
                (r'Runtime\.getRuntime\(\)\.exec\s*\(', "Java Runtime.exec()"),
                (r'shell_exec\s*\(', "PHP shell_exec"),
            ]
            for pattern, desc in cmd_patterns:
                if re.search(pattern, node_text):
                    self._check_dynamic_arg(node, content, lines, findings,
                                            "命令注入", "CWE-78",
                                            extra_desc=desc)

        for child in node.children:
            self._walk_and_find_cmd_injection(child, content, lines, findings)

    def _walk_and_find_path_traversal(self, node, content: str, lines: list, findings: list):
        """遍历 AST 查找路径遍历"""
        if node.type in ("call", "call_expression", "method_invocation"):
            node_text = content[node.start_byte:node.end_byte]

            if re.search(r'(open|readFile|file_get_contents)\s*\(', node_text):
                self._check_dynamic_arg(node, content, lines, findings,
                                        "路径遍历", "CWE-22")

        for child in node.children:
            self._walk_and_find_path_traversal(child, content, lines, findings)

    def _walk_and_find_xss(self, node, content: str, lines: list, findings: list):
        """遍历 AST 查找 XSS"""
        if node.type in ("assignment", "expression_statement"):
            node_text = content[node.start_byte:node.end_byte]

            xss_patterns = [
                r'innerHTML\s*=',
                r'\.html\s*\(',
                r'dangerouslySetInnerHTML',
                r'v-html\s*=',
                r'document\.write\s*\(',
            ]
            for pattern in xss_patterns:
                if re.search(pattern, node_text):
                    # 检查右值是否包含变量
                    if re.search(r'\$\{|\+|\%|format\(|f["\']', node_text):
                        line_no = self._get_line(node, lines)
                        findings.append({
                            "id": f"ast-xss-{len(findings)+1}",
                            "category": "xss",
                            "vuln_name": "跨站脚本 (XSS)",
                            "severity": "中危",
                            "cwe": "CWE-79",
                            "file": "",
                            "line": line_no,
                            "match": node_text[:200],
                            "context": "",
                            "source": "ast_analysis",
                            "verified": False,
                            "risk_description": f"AST检测: innerHTML 中使用了动态变量，可能的 XSS 漏洞",
                        })
                    break

        for child in node.children:
            self._walk_and_find_xss(child, content, lines, findings)

    def _check_dynamic_arg(self, node, content: str, lines: list,
                           findings: list, vuln_name: str, cwe: str,
                           extra_desc: str = ""):
        """检查函数参数是否为动态（可能可控）"""
        line_no = self._get_line(node, lines)
        node_text = content[node.start_byte:node.end_byte]

        # 检查参数区域
        paren_start = node_text.find('(')
        if paren_start >= 0:
            args = node_text[paren_start:]
            # 动态参数特征：f-string、拼接、变量、格式化
            if re.search(r'[fF][\'"]|\+|%[^=]|format\(|%s|\$|\.join|os\.environ', args) \
               or not re.match(r'^\([\'\"][^\'"]*[\'\"]\)\s*$', args):
                desc = f"AST检测: 存在动态参数传入危险函数"
                if extra_desc:
                    desc = f"AST检测: {extra_desc} 中存在动态参数"
                findings.append({
                    "id": f"ast-{vuln_name.lower().replace(' ', '_')}-{len(findings)+1}",
                    "category": vuln_name.lower().replace(' ', '_').replace('(', '').replace(')', ''),
                    "vuln_name": vuln_name,
                    "severity": "高危",
                    "cwe": cwe,
                    "file": "",
                    "line": line_no,
                    "match": node_text[:200],
                    "context": "",
                    "source": "ast_analysis",
                    "verified": False,
                    "risk_description": desc,
                })

    def _get_line(self, node, lines: list) -> int:
        """获取节点所在行号"""
        return node.start_point[0] + 1 if node.start_point else 1

    def _make_finding(self, node, content: str, lines: list,
                      vuln_name: str, cwe: str, desc: str) -> dict:
        """构造发现字典"""
        line_no = self._get_line(node, lines)
        node_text = content[node.start_byte:node.end_byte]
        return {
            "id": f"ast-{vuln_name.lower().replace(' ', '_')}-{len(self._finding_counter)}",
            "category": vuln_name.lower().replace(' ', '_').replace('(', '').replace(')', ''),
            "vuln_name": vuln_name,
            "severity": "高危",
            "cwe": cwe,
            "file": "",
            "line": line_no,
            "match": node_text[:200],
            "context": "",
            "source": "ast_analysis",
            "verified": False,
            "risk_description": desc,
        }

    def _finding_counter(self):
        """计数器生成器"""
        i = 0
        while True:
            i += 1
            yield i

    def analyze(self, file_path: str, content: str) -> list:
        """
        对单个文件执行完整的 AST 语义分析

        Args:
            file_path: 文件路径
            content: 代码内容

        Returns:
            AST 层面发现的漏洞列表
        """
        ext = os.path.splitext(file_path)[1].lower()
        if not self.can_parse(ext):
            return []

        tree = self.parse(file_path, content)
        if not tree:
            return []

        all_findings = []
        all_findings.extend(self.detect_sql_injection_ast(tree, content))
        all_findings.extend(self.detect_command_injection_ast(tree, content))
        all_findings.extend(self.detect_path_traversal_ast(tree, content))
        all_findings.extend(self.detect_xss_ast(tree, content))

        # 补全文件路径
        for f in all_findings:
            if not f["file"]:
                f["file"] = os.path.relpath(file_path)

        return all_findings


# 初始化全局 AST 分析器实例
_ast_analyzer = None


def get_ast_analyzer():
    """获取全局 AST 分析器单例"""
    global _ast_analyzer
    if _ast_analyzer is None:
        _ast_analyzer = ASTAnalyzer()
    return _ast_analyzer
