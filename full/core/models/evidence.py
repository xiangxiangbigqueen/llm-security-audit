"""证据链数据模型"""
from dataclasses import dataclass, field
from typing import List, Optional, Tuple


@dataclass
class DiscoveryEvidence:
    """发现阶段证据"""
    scanner_type: str = ""           # 发现来源(static_tool/llm/both)
    tool_output: str = ""            # 工具原始输出
    file_path: str = ""              # 漏洞文件路径
    line_numbers: Tuple[int, int] = (0, 0)  # 起止行号
    code_snippet: str = ""           # 相关代码片段
    data_flow: List[str] = field(default_factory=list)   # 数据流路径
    call_chain: List[str] = field(default_factory=list)  # 调用链


@dataclass
class ValidationEvidence:
    """验证阶段证据"""
    validator_judgment: str = ""     # CONFIRMED/REJECTED
    reasoning: str = ""              # 判定理由
    context_analyzed: List[str] = field(default_factory=list)  # 分析过的上下文文件
    defense_measures: List[str] = field(default_factory=list)  # 已识别的防护措施
    iteration_count: int = 0         # 反馈环迭代次数
    confidence: float = 0.0


@dataclass
class ExploitationEvidence:
    """利用阶段证据"""
    poc_code: str = ""               # PoC代码
    exploit_type: str = ""           # 利用方式
    preconditions: List[str] = field(default_factory=list)  # 前置条件
    expected_result: str = ""        # 预期利用结果
    impact_scope: str = ""           # 影响范围
    exploit_steps: List[str] = field(default_factory=list)


@dataclass
class EvidenceChain:
    """完整漏洞证据链"""
    vulnerability_id: str
    discovery: DiscoveryEvidence = field(default_factory=DiscoveryEvidence)
    validation: ValidationEvidence = field(default_factory=ValidationEvidence)
    exploitation: ExploitationEvidence = field(default_factory=ExploitationEvidence)

    def to_dict(self) -> dict:
        return {
            "vulnerability_id": self.vulnerability_id,
            "discovery": {
                "scanner_type": self.discovery.scanner_type,
                "tool_output": self.discovery.tool_output,
                "file_path": self.discovery.file_path,
                "data_flow": self.discovery.data_flow,
                "call_chain": self.discovery.call_chain,
            },
            "validation": {
                "judgment": self.validation.validator_judgment,
                "reasoning": self.validation.reasoning,
                "confidence": self.validation.confidence,
                "iteration_count": self.validation.iteration_count,
            },
            "exploitation": {
                "poc_code": self.exploitation.poc_code,
                "exploit_type": self.exploitation.exploit_type,
                "preconditions": self.exploitation.preconditions,
                "impact_scope": self.exploitation.impact_scope,
            },
        }