"""
LLM API 客户端模块（支持国内大模型 API）

【主流技术使用标注】
★ DeepSeek API: 通过国产大模型进行代码语义分析
★ OpenAI 兼容接口: 支持 DeepSeek / Qwen / GLM 等国内 API
★ 自动降级: API 不可用时自动降级到规则匹配
"""

import os
import json
import time
import re
from typing import Optional, Dict, Any


class LLMClient:
    """
    LLM API 客户端
    支持 OpenAI 兼容接口（DeepSeek / Qwen / GLM 等国内大模型）
    """

    def __init__(self, api_key: Optional[str] = None,
                 api_base: Optional[str] = None,
                 model: Optional[str] = None):
        # 默认使用 DeepSeek
        self.api_key = api_key or os.environ.get("LLM_API_KEY", "")
        self.api_base = api_base or os.environ.get("LLM_API_BASE",
                                                   "https://api.deepseek.com")
        self.model = model or os.environ.get("LLM_MODEL", "deepseek-chat")

        self.api_available = bool(self.api_key)
        self.stats = {
            "calls": 0,
            "total_tokens": 0,
            "success": 0,
            "failed": 0,
        }

        if self.api_available:
            provider = self._detect_provider()
            print(f"  🤖 LLM API 已连接 ({provider} | {self.model})")
        else:
            print(f"  ⚠️ 未设置 API Key，LLM 分析将跳过")
            print(f"    设置环境变量 LLM_API_KEY 即可启用")
            print(f"    支持的国内 API:")
            print(f"      - DeepSeek:  export LLM_API_KEY=sk-xxx")
            print(f"                  export LLM_API_BASE=https://api.deepseek.com")
            print(f"      - 通义千问:  export LLM_API_KEY=sk-xxx")
            print(f"                  export LLM_API_BASE=https://dashscope.aliyuncs.com/compatible-mode/v1")
            print(f"      - 智谱 GLM:  export LLM_API_KEY=xxx")
            print(f"                  export LLM_API_BASE=https://open.bigmodel.cn/api/paas/v4")

    def _detect_provider(self) -> str:
        """检测 API 提供商"""
        if "deepseek" in self.api_base.lower():
            return "DeepSeek (深度求索)"
        elif "dashscope" in self.api_base.lower():
            return "Qwen (通义千问)"
        elif "bigmodel" in self.api_base.lower():
            return "GLM (智谱)"
        elif "moonshot" in self.api_base.lower():
            return "Moonshot (月之暗面)"
        elif "baidu" in self.api_base.lower():
            return "ERNIE (百度文心)"
        elif "openai" in self.api_base.lower():
            return "OpenAI 兼容"
        return self.api_base

    def analyze_security(self, code: str, file_path: str = "",
                         vuln_type: str = "") -> Dict[str, Any]:
        """分析代码安全漏洞"""
        prompt = f"""你是一个顶尖的安全审计专家。请分析以下代码中的安全漏洞。

## 文件: {file_path or "未知"}
## 关注的漏洞类型: {vuln_type or "所有常见漏洞"}

## 代码:
```{os.path.splitext(file_path)[1].lstrip('.') if file_path else ''}
{code[:6000]}
```

## 分析要求：
1. 找出所有潜在的安全漏洞
2. 判断输入是否受攻击者控制
3. 评估漏洞严重程度
4. 给出修复建议

## 输出格式（仅 JSON）:
```json
{{
  "has_vulnerability": true/false,
  "findings": [
    {{
      "type": "漏洞类型",
      "severity": "高危/中危/低危/信息",
      "cwe": "CWE-编号",
      "location": "漏洞位置描述",
      "description": "漏洞描述",
      "attack_vector": "攻击路径",
      "fix_suggestion": "修复建议"
    }}
  ]
}}
```"""
        return self._call_api(prompt, max_tokens=2000)

    def verify_finding(self, code_snippet: str, vuln_name: str,
                       cwe: str, file_path: str) -> Dict[str, Any]:
        """验证单个漏洞发现"""
        prompt = f"""你是一个安全审计专家，请验证以下代码是否存在安全漏洞。

## 漏洞类型: {vuln_name}
## CWE: {cwe}
## 文件: {file_path}

## 代码片段:
```{os.path.splitext(file_path)[1].lstrip('.') if '.' in file_path else ''}
{code_snippet[:4000]}
```

## 验证要求：
请从以下维度分析：
1. 输入源是否受攻击者控制？
2. 是否有足够的防护/过滤/转义？
3. 数据流是否可达敏感操作？
4. 这是真实漏洞还是误报？

## 输出格式（仅 JSON）:
```json
{{
  "is_real_vulnerability": true/false,
  "confidence": "high/medium/low",
  "reasoning": "简要推理过程",
  "attack_vector": "攻击路径",
  "impact": "被利用后的影响",
  "fix_suggestion": "修复建议",
  "severity_rating": "critical/high/medium/low/info"
}}
```"""
        return self._call_api(prompt, max_tokens=1500)

    def _call_api(self, prompt: str, max_tokens: int = 2000,
                  temperature: float = 0.1) -> Dict[str, Any]:
        """调用 LLM API（OpenAI 兼容格式）"""
        self.stats["calls"] += 1

        if not self.api_available:
            return {"error": "API Key 未配置", "content": None}

        import requests

        try:
            resp = requests.post(
                f"{self.api_base.rstrip('/')}/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": "你是一个专业的安全审计专家，擅长代码安全分析。"},
                        {"role": "user", "content": prompt}
                    ],
                    "max_tokens": max_tokens,
                    "temperature": temperature,
                },
                timeout=120,
                proxies={"http": os.environ.get("HTTP_PROXY", ""),
                         "https": os.environ.get("HTTPS_PROXY", "")} or None,
            )

            if resp.status_code != 200:
                self.stats["failed"] += 1
                return {"error": f"API Error {resp.status_code}: {resp.text[:200]}"}

            data = resp.json()
            content = data["choices"][0]["message"]["content"]

            self.stats["success"] += 1
            usage = data.get("usage", {})
            self.stats["total_tokens"] += (
                usage.get("prompt_tokens", 0) + usage.get("completion_tokens", 0)
            )

            json_data = self._extract_json(content)
            return json_data or {"content": content}

        except requests.exceptions.ConnectTimeout:
            self.stats["failed"] += 1
            return {"error": "连接超时，请检查网络和 API 地址"}
        except requests.exceptions.ConnectionError:
            self.stats["failed"] += 1
            return {"error": "连接失败，请检查网络和 API 地址"}
        except Exception as e:
            self.stats["failed"] += 1
            return {"error": str(e)}

    def _extract_json(self, text: str) -> Optional[Dict]:
        """从文本中提取 JSON"""
        json_match = re.search(r'```(?:json)?\s*\n?(.*?)\n?```', text, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group(1))
            except json.JSONDecodeError:
                pass
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass
        return None

    def print_stats(self):
        """打印调用统计"""
        if self.stats["calls"] > 0:
            print(f"  📊 LLM API 统计:")
            print(f"    调用次数: {self.stats['calls']}")
            print(f"    成功: {self.stats['success']}")
            print(f"    失败: {self.stats['failed']}")
            print(f"    总 Token: {self.stats['total_tokens']}")


# 全局客户端实例
_llm_client = None


def get_llm_client(api_key: Optional[str] = None,
                   api_base: Optional[str] = None,
                   model: Optional[str] = None):
    """获取 LLM 客户端单例"""
    global _llm_client
    if _llm_client is None:
        _llm_client = LLMClient(api_key=api_key, api_base=api_base, model=model)
    return _llm_client
