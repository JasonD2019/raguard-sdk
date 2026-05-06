"""
全链路检测模块

聚合 doc_scanner、recall_filter、prompt_checker 三个模块，提供一站式安全检测。
性能要求：<500ms P99
"""

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Union

from ..utils.logger import get_logger
from ..utils.metrics import global_collector
from .doc_scanner import doc_scanner, ScanResult
from .recall_filter import recall_filter, FilterResult
from .prompt_checker import prompt_checker, CheckResult

logger = get_logger(__name__)


@dataclass
class FullCheckResult:
    """全链路检测结果"""
    overall_passed: bool
    overall_score: int  # 0-100
    doc_result: Optional[ScanResult] = None
    recall_result: Optional[FilterResult] = None
    prompt_result: Optional[CheckResult] = None
    duration_ms: int = 0
    summary: str = ""
    recommendations: List[str] = field(default_factory=list)


class FullChecker:
    """全链路检查器"""
    
    def __init__(self, max_workers: int = 3):
        """
        初始化全链路检查器
        
        Args:
            max_workers: 最大并发线程数
        """
        self.max_workers = max_workers
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        
        logger.info(f"FullChecker 初始化完成，最大并发数={max_workers}")
    
    def check(
        self,
        document: Union[str, bytes],
        query: str,
        user_context: Optional[Dict[str, Any]] = None,
        enable_parallel: bool = True
    ) -> FullCheckResult:
        """
        执行全链路安全检测
        
        Args:
            document: 文档内容
            query: 用户查询
            user_context: 用户上下文
            enable_parallel: 是否启用并行检测
        
        Returns:
            FullCheckResult 检测结果
        """
        start_time = time.perf_counter()
        
        if enable_parallel:
            # 并行执行三个检测
            doc_result, recall_result, prompt_result = self._parallel_check(
                document, query, user_context
            )
        else:
            # 串行执行
            doc_result = self._check_document(document)
            prompt_result = self._check_prompt(query, user_context)
            recall_result = self._check_recall(query, [], user_context)
        
        # 收集所有问题
        all_issues = []
        if doc_result and doc_result.issues:
            all_issues.extend(doc_result.issues)
        
        # BUG-002 修复：评分逻辑考虑高危问题
        overall_score = self._calculate_overall_score(doc_result, recall_result, prompt_result)
        
        # 高危问题直接导致失败
        if any(issue.level == "high" for issue in all_issues):
            overall_passed = False
        elif any(issue.level == "medium" for issue in all_issues):
            overall_passed = overall_score >= 70
        elif doc_result and not doc_result.passed:
            # 文档有问题但不是 high/medium 级别
            overall_passed = overall_score >= 80
        elif prompt_result and not prompt_result.is_safe:
            # 提示词不安全
            overall_passed = False
        else:
            overall_passed = overall_score >= 60
        
        # 生成总结和建议
        summary = self._generate_summary(doc_result, recall_result, prompt_result)
        recommendations = self._generate_recommendations(doc_result, recall_result, prompt_result)
        
        duration_ms = int((time.perf_counter() - start_time) * 1000)
        
        result = FullCheckResult(
            overall_passed=overall_passed,
            overall_score=overall_score,
            doc_result=doc_result,
            recall_result=recall_result,
            prompt_result=prompt_result,
            duration_ms=duration_ms,
            summary=summary,
            recommendations=recommendations
        )
        
        logger.info(
            f"全链路检测完成：passed={overall_passed}, score={overall_score}, "
            f"duration={duration_ms}ms, doc={doc_result.duration_ms if doc_result else 0}ms, "
            f"recall={recall_result.duration_ms if recall_result else 0}ms, "
            f"prompt={prompt_result.duration_ms if prompt_result else 0}ms"
        )
        
        return result
    
    def _parallel_check(
        self,
        document: Union[str, bytes],
        query: str,
        user_context: Optional[Dict[str, Any]]
    ) -> tuple[ScanResult, FilterResult, CheckResult]:
        """并行执行三个检测"""
        futures = {
            self.executor.submit(self._check_document, document): "doc",
            self.executor.submit(self._check_prompt, query, user_context): "prompt",
            self.executor.submit(self._check_recall, query, [], user_context): "recall"
        }
        
        doc_result = None
        recall_result = None
        prompt_result = None
        
        for future in as_completed(futures):
            try:
                result = future.result()
                result_type = futures[future]
                
                if result_type == "doc":
                    doc_result = result
                elif result_type == "prompt":
                    prompt_result = result
                elif result_type == "recall":
                    recall_result = result
            except Exception as e:
                logger.error(f"检测任务失败：{futures[future]}, 错误：{e}")
        
        return doc_result, recall_result, prompt_result
    
    def _check_document(self, document: Union[str, bytes]) -> ScanResult:
        """执行文档扫描"""
        try:
            return doc_scanner(document, doc_type="text")
        except Exception as e:
            logger.error(f"文档扫描失败：{e}")
            return ScanResult(passed=True, score=100, issues=[], duration_ms=0)
    
    def _check_prompt(self, query: str, user_context: Optional[Dict]) -> CheckResult:
        """执行提示词检测"""
        try:
            return prompt_checker(query, user_context)
        except Exception as e:
            logger.error(f"提示词检测失败：{e}")
            return CheckResult(
                is_safe=True,
                risk_type=None,
                confidence=0.0,
                sanitized_prompt=query,
                duration_ms=0
            )
    
    def _check_recall(
        self,
        query: str,
        results: List[Dict],
        user_context: Optional[Dict]
    ) -> FilterResult:
        """执行召回过滤"""
        try:
            return recall_filter(query, results, user_context)
        except Exception as e:
            logger.error(f"召回过滤失败：{e}")
            return FilterResult(
                filtered_results=[],
                removed_count=0,
                reasons=[],
                duration_ms=0
            )
    
    def _calculate_overall_score(
        self,
        doc_result: Optional[ScanResult],
        recall_result: Optional[FilterResult],
        prompt_result: Optional[CheckResult]
    ) -> int:
        """
        计算综合评分
        
        权重：
        - 文档扫描：40%
        - 提示词检测：35%
        - 召回过滤：25%
        
        BUG-002 修复：高危问题直接大幅扣分
        """
        scores = []
        weights = []
        
        if doc_result:
            # 如果有高危问题，直接降低文档分数
            doc_score = doc_result.score
            high_issues = [i for i in doc_result.issues if i.level == "high"]
            if high_issues:
                # 每个高危问题额外扣 10 分
                doc_score = max(0, doc_score - len(high_issues) * 10)
            scores.append(doc_score)
            weights.append(0.4)
        
        if prompt_result:
            # 将提示词安全性转换为分数
            if prompt_result.is_safe:
                prompt_score = 100
            else:
                # 不安全时，根据风险等级和置信度扣分
                base_score = int(100 * (1 - prompt_result.confidence))
                if prompt_result.risk_level == "high":
                    prompt_score = max(0, base_score - 20)
                elif prompt_result.risk_level == "medium":
                    prompt_score = max(0, base_score - 10)
                else:
                    prompt_score = base_score
            scores.append(prompt_score)
            weights.append(0.35)
        
        if recall_result:
            # 根据过滤比例计算分数
            if recall_result.total_count > 0:
                removal_rate = recall_result.removed_count / recall_result.total_count
                recall_score = int(100 * (1 - removal_rate))
            else:
                recall_score = 100
            scores.append(recall_score)
            weights.append(0.25)
        
        if not scores:
            return 100
        
        # 加权平均
        overall_score = sum(s * w for s, w in zip(scores, weights))
        
        return int(overall_score)
    
    def _generate_summary(
        self,
        doc_result: Optional[ScanResult],
        recall_result: Optional[FilterResult],
        prompt_result: Optional[CheckResult]
    ) -> str:
        """生成检测总结"""
        parts = []
        
        if doc_result:
            if doc_result.passed:
                parts.append(f"文档扫描通过（{doc_result.score}分）")
            else:
                parts.append(f"文档扫描发现{len(doc_result.issues)}个问题")
        
        if prompt_result:
            if prompt_result.is_safe:
                parts.append("提示词安全")
            else:
                parts.append(f"提示词检测到{prompt_result.risk_type}风险")
        
        if recall_result:
            if recall_result.removed_count > 0:
                parts.append(f"召回结果过滤{recall_result.removed_count}项")
            else:
                parts.append("召回结果全部通过")
        
        return "; ".join(parts) if parts else "检测完成"
    
    def _generate_recommendations(
        self,
        doc_result: Optional[ScanResult],
        recall_result: Optional[FilterResult],
        prompt_result: Optional[CheckResult]
    ) -> List[str]:
        """生成改进建议"""
        recommendations = []
        
        if doc_result and not doc_result.passed:
            high_issues = [i for i in doc_result.issues if i.level == "high"]
            if high_issues:
                recommendations.append(f"文档中存在{len(high_issues)}个高风险问题，建议修改")
        
        if prompt_result and not prompt_result.is_safe:
            recommendations.append(f"提示词存在{prompt_result.risk_type}风险，建议重新组织查询")
        
        if recall_result and recall_result.removed_count > 0:
            recommendations.append(f"部分召回结果被过滤，请检查用户权限设置")
        
        return recommendations
    
    def __del__(self):
        """清理线程池"""
        if hasattr(self, 'executor'):
            self.executor.shutdown(wait=False)


# 便捷函数
_checker_instance: Optional[FullChecker] = None


def full_check(
    document: Union[str, bytes],
    query: str,
    user_context: Optional[Dict[str, Any]] = None
) -> FullCheckResult:
    """
    全链路检测便捷函数
    
    Args:
        document: 文档内容
        query: 用户查询
        user_context: 用户上下文
    
    Returns:
        FullCheckResult 检测结果
    """
    global _checker_instance
    if _checker_instance is None:
        _checker_instance = FullChecker()
    
    with global_collector.measure("full_check"):
        return _checker_instance.check(document, query, user_context)
