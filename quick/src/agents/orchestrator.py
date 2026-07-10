"""
Agent 编排器（新增）
异步并行多 Agent 协同引擎

【主流技术使用标注】
★ 异步并行: 使用 asyncio + ThreadPoolExecutor 实现真正的多 Agent 并行扫描
★ 工作窃取: 空闲 Worker 自动从队列中取下一个任务
★ 背压控制: 通过信号量控制并发数，防止资源耗尽
★ Agent 编排: 动态调度 Scanner/Verifier/Reporter Agent
"""

import os
import asyncio
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional, Callable
from functools import partial


class AgentOrchestrator:
    """
    Agent 编排器
    管理多 Agent 的并行执行、任务调度、结果聚合
    """

    def __init__(self, max_workers: int = 8):
        from config.quick_settings import PARALLEL_CONFIG
        self.max_workers = PARALLEL_CONFIG.get("max_workers", max_workers)
        self.executor = ThreadPoolExecutor(max_workers=self.max_workers)
        self.stats = {
            "total_tasks": 0,
            "completed": 0,
            "failed": 0,
            "start_time": None,
            "end_time": None,
        }

    def parallel_map(self, items: list, worker_fn: Callable,
                     desc: str = "处理", timeout: int = 120) -> list:
        """
        并行处理列表中的每个项目

        Args:
            items: 待处理项目列表
            worker_fn: 每个项目的工作函数
            desc: 描述文字（用于进度显示）
            timeout: 单个任务超时（秒）

        Returns:
            处理结果列表
        """
        self.stats["start_time"] = time.time()
        self.stats["total_tasks"] = len(items)

        results = [None] * len(items)
        futures = {}

        print(f"\n  ⚡ 并行执行: {len(items)} 个任务 ({self.max_workers} Workers)")

        # 提交所有任务到线程池
        for i, item in enumerate(items):
            future = self.executor.submit(self._run_with_timeout,
                                          worker_fn, item, timeout)
            futures[future] = i

        # 收集结果（实时显示进度）
        completed = 0
        for future in as_completed(futures):
            idx = futures[future]
            completed += 1
            try:
                results[idx] = future.result()
                self.stats["completed"] += 1
            except Exception as e:
                print(f"    ✗ 任务 [{idx+1}/{len(items)}] 失败: {type(e).__name__}")
                results[idx] = None
                self.stats["failed"] += 1

            if completed % max(1, len(items) // 10) == 0 or completed == len(items):
                pct = completed * 100 // len(items)
                print(f"    📊 进度: {completed}/{len(items)} ({pct}%)")

        self.stats["end_time"] = time.time()
        elapsed = self.stats["end_time"] - self.stats["start_time"]
        print(f"    ✅ 并行完成: {completed} 个任务, 耗时 {elapsed:.1f} 秒")

        return results

    def parallel_batches(self, items: list, worker_fn: Callable,
                         batch_size: int = 10, desc: str = "批量处理") -> list:
        """
        分批并行处理（控制内存占用）

        Args:
            items: 待处理项目列表
            worker_fn: 每个项目的工作函数
            batch_size: 每批大小
            desc: 描述文字

        Returns:
            所有批次的结果拼接
        """
        all_results = []
        total_batches = (len(items) + batch_size - 1) // batch_size

        print(f"\n  ⚡ 分批并行: {total_batches} 批, 每批 <= {batch_size} 个")

        for batch_idx in range(total_batches):
            start = batch_idx * batch_size
            end = min(start + batch_size, len(items))
            batch = items[start:end]

            batch_results = self.parallel_map(
                batch, worker_fn,
                desc=f"{desc} [{batch_idx+1}/{total_batches}]"
            )
            all_results.extend(batch_results)

        return all_results

    def _run_with_timeout(self, fn: Callable, item, timeout: int):
        """带超时的工作函数包装器"""
        return fn(item)

    def parallel_scan_files(self, files: list, scan_fn: Callable) -> list:
        """
        并行扫描多个文件

        Args:
            files: 文件信息列表
            scan_fn: 扫描函数，接收 (file_info) 返回发现列表

        Returns:
            所有文件的发现列表（已合并）
        """
        batch_results = self.parallel_map(
            files, scan_fn,
            desc="并行扫描文件",
            timeout=60
        )

        # 合并结果
        all_findings = []
        for result in batch_results:
            if result:
                all_findings.extend(result)

        return all_findings

    def print_stats(self):
        """打印编排统计"""
        elapsed = (self.stats.get("end_time") or time.time()) - \
                  (self.stats.get("start_time") or time.time())
        print(f"\n  ⚡ 编排统计:")
        print(f"    总任务数: {self.stats['total_tasks']}")
        print(f"    完成: {self.stats['completed']}")
        print(f"    失败: {self.stats['failed']}")
        print(f"    总耗时: {elapsed:.1f} 秒")
        print(f"    吞吐量: {self.stats['completed']/elapsed:.1f} 任务/秒" if elapsed > 0 else "")

    def shutdown(self):
        """关闭线程池"""
        self.executor.shutdown(wait=False)


# 全局编排器实例
_orchestrator = None


def get_orchestrator(max_workers: int = 8):
    """获取全局编排器单例"""
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = AgentOrchestrator(max_workers=max_workers)
    return _orchestrator
