"""DeepSeek API客户端封装"""
import asyncio
import json
import logging
from typing import List, Dict, Optional

import aiohttp

from config.settings import (
    DEEPSEEK_API_KEY,
    DEEPSEEK_BASE_URL,
    DEEPSEEK_MODEL,
    LLM_TEMPERATURE,
    LLM_MAX_TOKENS,
    LLM_RETRY_COUNT,
    LLM_RETRY_DELAY,
)

logger = logging.getLogger(__name__)


class DeepSeekClient:
    """DeepSeek Chat API 客户端"""

    def __init__(self, api_key: str = None, base_url: str = None):
        self.api_key = api_key or DEEPSEEK_API_KEY
        self.base_url = base_url or DEEPSEEK_BASE_URL
        self.model = DEEPSEEK_MODEL
        self.session: Optional[aiohttp.ClientSession] = None

    async def _get_session(self) -> aiohttp.ClientSession:
        if self.session is None or self.session.closed:
            self.session = aiohttp.ClientSession()
        return self.session

    async def chat(
        self,
        messages: List[Dict[str, str]],
        temperature: float = None,
        max_tokens: int = None,
    ) -> str:
        """调用DeepSeek-Chat API，返回助手回复文本"""
        temperature = temperature or LLM_TEMPERATURE
        max_tokens = max_tokens or LLM_MAX_TOKENS

        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
       }

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        for attempt in range(LLM_RETRY_COUNT):
            try:
                session = await self._get_session()
                async with session.post(
                    f"{self.base_url}/chat/completions",
                    headers=headers,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=120),
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        content = data["choices"][0]["message"]["content"]
                        logger.debug(f"LLM响应成功, 长度: {len(content)}")
                        return content
                    else:
                        error_text = await resp.text()
                        logger.warning(f"API错误 (尝试 {attempt+1}): {resp.status} - {error_text}")
            except Exception as e:
                logger.warning(f"API调用异常 (尝试 {attempt+1}): {e}")

            if attempt < LLM_RETRY_COUNT - 1:
                await asyncio.sleep(LLM_RETRY_DELAY * (attempt + 1))

        raise RuntimeError("DeepSeek API调用失败，已达最大重试次数")

    async def chat_json(self, messages: List[Dict[str, str]], **kwargs) -> dict:
        """调用API并解析JSON响应，带增强容错"""
        response = await self.chat(messages, **kwargs)
        # 尝试从响应中提取JSON
        json_str = response

        # 1. 尝试从markdown代码块中提取
        if "```json" in response:
            json_str = response.split("```json")[1].split("```")[0].strip()
        elif "```" in response:
            json_str = response.split("```")[1].split("```")[0].strip()

        # 2. 尝试直接解析
        try:
            return json.loads(json_str)
        except json.JSONDecodeError:
            pass

        # 3. 容错：修复常见JSON格式问题
        try:
            import re
            # 去除尾部多余逗号 (trailing commas)
            fixed = re.sub(r',\s*([}\]])', r'\1', json_str)
            # 修复单引号为双引号
            fixed = fixed.replace("'", '"')
            return json.loads(fixed)
        except (json.JSONDecodeError, Exception):
            pass

        # 4. 尝试提取第一个 { ... } 块
        try:
            start = json_str.index('{')
            # 找到匹配的最后一个 }
            depth = 0
            end = start
            for i in range(start, len(json_str)):
                if json_str[i] == '{':
                    depth += 1
                elif json_str[i] == '}':
                    depth -= 1
                    if depth == 0:
                        end = i
                        break
            extracted = json_str[start:end+1]
            return json.loads(extracted)
        except (ValueError, json.JSONDecodeError):
            pass

        # 5. 最终降级：返回空漏洞列表
        logger.warning(f"JSON解析失败，返回空结果。原始响应: {response[:200]}")
        return {"vulnerabilities": [], "validations": [], "exploits": []}

    async def close(self):
        """关闭会话"""
        if self.session and not self.session.closed:
            await self.session.close()