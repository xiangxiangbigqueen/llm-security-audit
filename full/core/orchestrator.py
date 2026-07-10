"""编排引擎 - 流水线调度 + 反馈环控制"""
import logging
import time
from typing import List, Dict, Optional, Callable
from dataclasses import dataclass

from core.llm.deepseek_client import DeepSeekClient
from core.agents.scanner_agent import ScannerAgent
from core.agents.validator_agent import ValidatorAgent
from core.agents.exploiter_agent import ExploiterAgent
from core.agents.reporter_agent import ReporterAgent
from core.models.vulnerability import Vulnerability
from core.models.project import ProjectMetadata
from config.full_settings import FEEDBACK_MAX_ITERATIONS

logger = logging.getLogger(__name__)


@dataclass
class AuditResult:
    """审计结果"""
    project: ProjectMetadata
    vulnerabilities: List[Vulnerability]
    report_data: Dict
    duration: float = 0.0
    iterations: int = 0


class Orchestrator:
    """编排引擎 - 管理多智能体协作流程"""

    def __init__(self, llm_client: DeepSeekClient = None):
        self.llm_client = llm_client or DeepSeekClient()
        self.scanner = ScannerAgent(self.llm_client)
        self.validator = ValidatorAgent(self.llm_client)
        self.exploiter = ExploiterAgent(self.llm_client)
        self.reporter = ReporterAgent(self.llm_client)
        self._progress_callback: Optional[Callable] = None
        self._log_callback: Optional[Callable] = None
        self._is_cancelled = False

    def set_progress_callback(self, callback: Callable):
        """设置进度回调"""
        self._progress_callback = callback
        # 传递给各智能体
        for agent in [self.scanner, self.validator, self.exploiter, self.reporter]:
            agent.on_progress(self._on_agent_progress)

    def set_log_callback(self, callback: Callable):
        """设置日志回调"""
        self._log_callback = callback

    def cancel(self):
        """取消审计"""
        self._is_cancelled = True

    def _on_agent_progress(self, agent_name: str, progress: float, message: str):
        """智能体进度回调"""
        if self._progress_callback:
            self._progress_callback(agent_name, progress, message)
        if self._log_callback and message:
            self._log_callback(agent_name, message)

    async def run_audit(self, project: ProjectMetadata) -> AuditResult:
        """执行完整审计流程"""
        start_time = time.time()
        self._is_cancelled = False

        logger.info(f"开始审计项目: {project.name}")
        self._on_agent_progress("Orchestrator", 0.0, f"开始审计项目: {project.name}")

        # 阶段1: 扫描
        self._on_agent_progress("Orchestrator", 0.1, "阶段1: 代码扫描")
        scan_results = await self.scanner.scan(project)

        if self._is_cancelled:
            return AuditResult(project=project, vulnerabilities=[], report_data={})

        if not scan_results:
            self._on_agent_progress("Orchestrator", 1.0, "未发现潜在漏洞")
            report_data = await self.reporter.generate(project, [])
            return AuditResult(project=project, vulnerabilities=[], report_data=report_data,
                             duration=time.time() - start_time)

        # 阶段2: 验证 (带反馈环)
        self._on_agent_progress("Orchestrator", 0.4, "阶段2: 漏洞验证")
        iteration = 0
        confirmed_vulns = []
        pending_results = scan_results

        while iteration < FEEDBACK_MAX_ITERATIONS and not self._is_cancelled:
            validation = await self.validator.validate(pending_results, project)

            confirmed_vulns.extend(validation["confirmed"])
            need_more = validation["need_more_context"]

            if not need_more:
                break

            # 反馈环: 打回Scanner补充分析
            self._on_agent_progress("Orchestrator", 0.5,
                                   f"反馈环迭代 #{iteration+1}: 需补充分析 {len(need_more)} 个漏洞")
            context_info = "\n".join([v.validation_reasoning for v in need_more])
            pending_results = await self.scanner.rescan_with_context(need_more, context_info)
            iteration += 1

        if self._is_cancelled:
            return AuditResult(project=project, vulnerabilities=confirmed_vulns, report_data={})

        # 阶段3: PoC生成
        self._on_agent_progress("Orchestrator", 0.7, "阶段3: PoC生成")
        if confirmed_vulns:
            confirmed_vulns = await self.exploiter.generate_pocs(confirmed_vulns, project)

        if self._is_cancelled:
            return AuditResult(project=project, vulnerabilities=confirmed_vulns, report_data={})

        # 阶段4: 报告生成
        self._on_agent_progress("Orchestrator", 0.9, "阶段4: 生成报告")
        report_data = await self.reporter.generate(project, confirmed_vulns)

        duration = time.time() - start_time
        self._on_agent_progress("Orchestrator", 1.0,
                               f"审计完成! 耗时{duration:.1f}秒, 发现{len(confirmed_vulns)}个确认漏洞")

        return AuditResult(
            project=project,
            vulnerabilities=confirmed_vulns,
            report_data=report_data,
            duration=duration,
            iterations=iteration,
        )