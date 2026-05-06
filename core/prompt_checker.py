"""
提示词检测模块

检测提示词注入和越狱攻击。
性能要求：<100ms P99

增强功能（2026-04-14）：
- 集成 ragshield-rules 规则库（900+ 模式）
- 使用统一 RulesLoader 加载规则
"""

import json
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ..utils.logger import get_logger
from ..utils.metrics import global_collector
from .rules_loader import RulesLoader

logger = get_logger(__name__)


@dataclass
class CheckResult:
    """提示词检测结果"""
    is_safe: bool
    risk_type: Optional[str]  # injection|jailbreak|none
    confidence: float  # 0.0-1.0
    sanitized_prompt: str
    duration_ms: int = 0
    matched_rules: List[str] = None
    risk_level: str = "none"  # none|low|medium|high

    def __post_init__(self):
        if self.matched_rules is None:
            self.matched_rules = []


class PromptChecker:
    """提示词检查器（增强版 - 使用 ragshield-rules）"""

    def __init__(self, rules_dir: Optional[str] = None):
        """
        初始化提示词检查器

        Args:
            rules_dir: 规则文件目录（可选，默认使用 ragshield-rules）
        """
        # 使用统一规则加载器
        self.loader = RulesLoader(rules_dir)

        # 加载并编译规则
        self.injection_rules = self.loader.load_category("injection")
        self.jailbreak_rules = self.loader.load_category("jailbreak")

        # 预编译规则（提高性能）
        self._injection_patterns = self.loader.compile_patterns(self.injection_rules)
        self._jailbreak_patterns = self.loader.compile_patterns(self.jailbreak_rules)

        logger.info(f"PromptChecker 初始化完成（ragshield-rules），加载 {len(self.injection_rules)} 条注入规则，"
                   f"{len(self.jailbreak_rules)} 条越狱规则")

    def check(self, prompt: str, context: Optional[Dict] = None) -> CheckResult:
        """
        检查提示词安全性

        Args:
            prompt: 用户输入的提示词
            context: 上下文信息（可选）

        Returns:
            CheckResult 检测结果
        """
        start_time = time.perf_counter()
        
        # 检测注入
        injection_matches = self._check_rules(prompt, self._injection_patterns)
        
        # 检测越狱
        jailbreak_matches = self._check_rules(prompt, self._jailbreak_patterns)
        
        # 合并结果
        all_matches = injection_matches + jailbreak_matches
        
        # 确定风险类型和等级
        if injection_matches and jailbreak_matches:
            risk_type = "injection+jailbreak"
            risk_level = "high"
        elif injection_matches:
            risk_type = "injection"
            risk_level = self._get_max_level(injection_matches)
        elif jailbreak_matches:
            risk_type = "jailbreak"
            risk_level = self._get_max_level(jailbreak_matches)
        else:
            risk_type = None
            risk_level = "none"
        
        # 计算置信度
        confidence = self._calculate_confidence(all_matches)
        
        # 生成净化后的提示词
        sanitized = self._sanitize_prompt(prompt, all_matches)
        
        # BUG-003 修复：有匹配规则就认为不安全
        is_safe = len(all_matches) == 0
        
        duration_ms = int((time.perf_counter() - start_time) * 1000)
        
        result = CheckResult(
            is_safe=is_safe,
            risk_type=risk_type,
            confidence=confidence,
            sanitized_prompt=sanitized,
            duration_ms=duration_ms,
            matched_rules=[m["rule_id"] for m in all_matches],
            risk_level=risk_level
        )
        
        logger.info(f"提示词检测完成：safe={is_safe}, risk={risk_type}, confidence={confidence:.2f}, {duration_ms}ms")
        
        return result
    
    def _check_rules(self, text: str, compiled_rules: List[Tuple[dict, Optional[re.Pattern]]]) -> List[dict]:
        """
        检查文本是否匹配规则
        
        Returns:
            匹配的规则列表
        """
        matches = []
        
        for rule, pattern in compiled_rules:
            if pattern is None:
                continue
            
            # BUG-003 修复：统一使用原文本进行匹配（正则已有 IGNORECASE 标志）
            if pattern.search(text):
                matches.append(rule)
        
        return matches
    
    def _get_max_level(self, matches: List[dict]) -> str:
        """获取最高风险等级"""
        level_order = {"high": 3, "medium": 2, "low": 1}
        max_level = "low"
        max_value = 0
        
        for match in matches:
            level = match.get("level", "low")
            value = level_order.get(level, 0)
            if value > max_value:
                max_value = value
                max_level = level
        
        return max_level
    
    def _calculate_confidence(self, matches: List[dict]) -> float:
        """
        计算置信度
        
        基于匹配规则的权重和数量
        """
        if not matches:
            return 0.0
        
        # 取最高权重
        max_weight = max(m.get("confidence_weight", 0.5) for m in matches)
        
        # 多个匹配增加置信度
        count_bonus = min(0.2, len(matches) * 0.05)
        
        confidence = min(1.0, max_weight + count_bonus)
        
        return round(confidence, 2)
    
    def _sanitize_prompt(self, prompt: str, matches: List[dict]) -> str:
        """
        净化提示词，移除或标记风险内容
        
        MVP 版本：简单标记
        """
        if not matches:
            return prompt
        
        # 如果检测到高风险，返回标记版本
        if any(m.get("level") == "high" for m in matches):
            return "[已过滤] " + prompt
        
        # 中低风险，返回原文
        return prompt


# 便捷函数
_checker_instance: Optional[PromptChecker] = None


def prompt_checker(prompt: str, context: Optional[Dict] = None) -> CheckResult:
    """
    提示词检测便捷函数
    
    Args:
        prompt: 用户输入的提示词
        context: 上下文信息
    
    Returns:
        CheckResult 检测结果
    """
    global _checker_instance
    if _checker_instance is None:
        _checker_instance = PromptChecker()
    
    with global_collector.measure("prompt_checker"):
        return _checker_instance.check(prompt, context)
