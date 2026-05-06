"""
RAGShield 检测引擎

统一集成所有检测器和评分算法，提供一站式安全检测服务。
"""

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Union

from ..utils.logger import get_logger
from ..utils.metrics import global_collector
from .risk_score import (
    RiskScorer,
    RiskLevel,
    calculate_risk_from_issues,
    Vulnerability,
)
from .prompt_checker import prompt_checker, CheckResult
from .doc_scanner import doc_scanner, ScanResult

logger = get_logger(__name__)


@dataclass
class EngineResult:
    """引擎检测结果"""
    passed: bool
    overall_score: int  # 0-100
    risk_level: str  # none|low|medium|high|critical
    duration_ms: int = 0
    prompt_result: Optional[CheckResult] = None
    doc_result: Optional[ScanResult] = None
    issues: List[Dict] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class DetectionEngine:
    """检测引擎"""
    
    def __init__(self, enable_risk_v2: bool = True):
        """
        初始化检测引擎
        
        Args:
            enable_risk_v2: 是否启用 v2 风险评分算法
        """
        self.enable_risk_v2 = enable_risk_v2
        self.risk_scorer = RiskScorer() if enable_risk_v2 else None
        
        logger.info(f"DetectionEngine 初始化完成，risk_v2={enable_risk_v2}")
    
    def detect(
        self,
        document: Optional[Union[str, bytes]] = None,
        query: Optional[str] = None,
        user_context: Optional[Dict[str, Any]] = None,
        enable_doc_scan: bool = True,
        enable_prompt_check: bool = True
    ) -> EngineResult:
        """
        执行全面安全检测
        
        Args:
            document: 文档内容（可选）
            query: 用户查询/提示词（可选）
            user_context: 用户上下文（可选）
            enable_doc_scan: 是否启用文档扫描
            enable_prompt_check: 是否启用提示词检测
        
        Returns:
            EngineResult 检测结果
        """
        start_time = time.perf_counter()
        
        all_issues = []
        prompt_result = None
        doc_result = None
        
        # 1. 文档扫描
        if enable_doc_scan and document:
            try:
                doc_result = doc_scanner(document, doc_type="text")
                if doc_result.issues:
                    all_issues.extend([
                        {
                            "level": issue.level,
                            "category": issue.category if hasattr(issue, 'category') else "document",
                            "description": issue.description if hasattr(issue, 'description') else str(issue),
                            "source": "doc_scanner"
                        }
                        for issue in doc_result.issues
                    ])
            except Exception as e:
                logger.error(f"文档扫描失败：{e}")
        
        # 2. 提示词检测
        if enable_prompt_check and query:
            try:
                prompt_result = prompt_checker(query, user_context)
                if not prompt_result.is_safe:
                    all_issues.append({
                        "level": prompt_result.risk_level,
                        "category": prompt_result.risk_type or "prompt_injection",
                        "description": f"Detected {prompt_result.risk_type} attack",
                        "source": "prompt_checker",
                        "confidence": prompt_result.confidence
                    })
            except Exception as e:
                logger.error(f"提示词检测失败：{e}")
        
        # 3. 风险评分
        if self.enable_risk_v2 and all_issues:
            risk_result = calculate_risk_from_issues(all_issues, user_context)
            overall_score = risk_result.overall_score
            risk_level = risk_result.risk_level.value
            recommendations = risk_result.recommendations
        else:
            # 回退到 v1 评分逻辑
            overall_score, risk_level = self._calculate_score_v1(all_issues, doc_result, prompt_result)
            recommendations = self._generate_recommendations_v1(all_issues, risk_level)
        
        # 4. 判定是否通过
        passed = self._determine_pass(overall_score, risk_level, all_issues)
        
        duration_ms = int((time.perf_counter() - start_time) * 1000)
        
        result = EngineResult(
            passed=passed,
            overall_score=overall_score,
            risk_level=risk_level,
            duration_ms=duration_ms,
            prompt_result=prompt_result,
            doc_result=doc_result,
            issues=all_issues,
            recommendations=recommendations,
            metadata={
                "risk_v2_enabled": self.enable_risk_v2,
                "issue_count": len(all_issues),
                "doc_scan_enabled": enable_doc_scan,
                "prompt_check_enabled": enable_prompt_check
            }
        )
        
        logger.info(
            f"引擎检测完成：passed={passed}, score={overall_score}, "
            f"level={risk_level}, issues={len(all_issues)}, {duration_ms}ms"
        )
        
        return result
    
    def _calculate_score_v1(
        self,
        issues: List[Dict],
        doc_result: Optional[ScanResult],
        prompt_result: Optional[CheckResult]
    ) -> tuple[int, str]:
        """v1 评分逻辑（向后兼容）"""
        if not issues:
            return 100, "none"
        
        # 简单扣分逻辑
        score = 100
        for issue in issues:
            level = issue.get("level", "low")
            if level == "critical":
                score -= 40
            elif level == "high":
                score -= 25
            elif level == "medium":
                score -= 15
            elif level == "low":
                score -= 5
        
        score = max(0, score)
        
        # 确定风险等级
        if score >= 80:
            risk_level = "low"
        elif score >= 60:
            risk_level = "medium"
        elif score >= 40:
            risk_level = "high"
        else:
            risk_level = "critical"
        
        return score, risk_level
    
    def _generate_recommendations_v1(
        self,
        issues: List[Dict],
        risk_level: str
    ) -> List[str]:
        """v1 建议生成（向后兼容）"""
        recommendations = []
        
        if risk_level == "critical":
            recommendations.append("【紧急】检测到严重风险，建议立即处理")
        elif risk_level == "high":
            recommendations.append("【高危】检测到高风险，建议优先修复")
        
        if issues:
            categories = {}
            for issue in issues:
                cat = issue.get("category", "unknown")
                categories[cat] = categories.get(cat, 0) + 1
            
            for cat, count in categories.items():
                recommendations.append(f"{cat}类问题{count}个，建议排查")
        
        if not recommendations:
            recommendations.append("当前风险可控，建议定期检测")
        
        return recommendations
    
    def _determine_pass(
        self,
        overall_score: int,
        risk_level: str,
        issues: List[Dict]
    ) -> bool:
        """判定是否通过检测"""
        # 有严重风险直接失败
        if risk_level == "critical":
            return False
        
        # 高风险且分数低于阈值失败
        if risk_level == "high" and overall_score < 50:
            return False
        
        # 中风险且分数低于阈值失败
        if risk_level == "medium" and overall_score < 60:
            return False
        
        # 其他情况通过
        return overall_score >= 60


# 便捷函数
_engine_instance: Optional[DetectionEngine] = None


def detect(
    document: Optional[Union[str, bytes]] = None,
    query: Optional[str] = None,
    user_context: Optional[Dict[str, Any]] = None
) -> EngineResult:
    """
    便捷检测函数
    
    Args:
        document: 文档内容
        query: 用户查询
        user_context: 用户上下文
    
    Returns:
        EngineResult 检测结果
    """
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = DetectionEngine(enable_risk_v2=True)
    
    with global_collector.measure("detection_engine"):
        return _engine_instance.detect(document, query, user_context)


def quick_check(text: str) -> EngineResult:
    """
    快速检查（仅提示词检测）
    
    Args:
        text: 待检查文本
    
    Returns:
        EngineResult 检测结果
    """
    return detect(query=text)
