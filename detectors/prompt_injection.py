"""
提示词注入检测器

基于规则的提示词注入检测。
"""

from dataclasses import dataclass
from typing import Dict, List, Optional

from ..core.prompt_checker import prompt_checker
from ..utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class InjectionResult:
    """注入检测结果"""
    detected: bool
    risk_type: Optional[str]
    confidence: float
    details: List[str]
    duration_ms: int


class PromptInjectionDetector:
    """提示词注入检测器"""
    
    def __init__(self):
        logger.info("PromptInjectionDetector 初始化完成")
    
    def detect(self, text: str, context: Optional[Dict] = None) -> InjectionResult:
        """
        检测提示词注入
        
        Args:
            text: 待检测文本
            context: 上下文信息
        
        Returns:
            InjectionResult 检测结果
        """
        import time
        start = time.perf_counter()
        
        result = prompt_checker(text, context)
        
        duration_ms = int((time.perf_counter() - start) * 1000)
        
        return InjectionResult(
            detected=not result.is_safe,
            risk_type=result.risk_type,
            confidence=result.confidence,
            details=result.matched_rules,
            duration_ms=duration_ms
        )


# 便捷函数
_detector = PromptInjectionDetector()


def detect_injection(text: str, context: Optional[Dict] = None) -> InjectionResult:
    """便捷检测函数"""
    return _detector.detect(text, context)
