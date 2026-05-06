"""
召回过滤模块

根据用户权限过滤召回结果，防止越权访问。
性能要求：<100ms P99
"""

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..utils.logger import get_logger
from ..utils.metrics import global_collector

logger = get_logger(__name__)


@dataclass
class FilterResult:
    """过滤结果"""
    filtered_results: List[Dict[str, Any]]
    removed_count: int
    reasons: List[str]
    duration_ms: int
    total_count: int = 0


class RecallFilter:
    """召回过滤器"""
    
    # 权限级别映射
    PERMISSION_LEVELS = {
        "public": 1,
        "internal": 2,
        "confidential": 3,
        "secret": 4
    }
    
    # 角色权限映射
    ROLE_PERMISSIONS = {
        "guest": 1,
        "user": 2,
        "staff": 3,
        "admin": 4,
        "superadmin": 5
    }
    
    def __init__(self, rules_dir: Optional[str] = None):
        """
        初始化召回过滤器
        
        Args:
            rules_dir: 规则文件目录
        """
        self.rules_dir = Path(rules_dir) if rules_dir else Path(__file__).parent.parent / "rules"
        self.sensitive_words = self._load_sensitive_words()
        
        logger.info(f"RecallFilter 初始化完成，加载 {len(self.sensitive_words)} 条敏感词")
    
    def _load_sensitive_words(self) -> List[str]:
        """加载敏感词列表"""
        rules_path = self.rules_dir / "sensitive_words.json"
        if not rules_path.exists():
            logger.warning(f"敏感词规则文件不存在：{rules_path}")
            return []
        
        try:
            with open(rules_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                words = []
                for rule in data.get("rules", []):
                    words.extend(rule.get("patterns", []))
                return words
        except Exception as e:
            logger.error(f"加载敏感词失败：{e}")
            return []
    
    def _contains_sensitive_content(self, content: str) -> bool:
        """检查是否包含敏感内容"""
        content_lower = content.lower()
        for word in self.sensitive_words:
            if word.lower() in content_lower:
                return True
        return False
    
    def filter(
        self,
        query: str,
        results: List[Dict[str, Any]],
        user_context: Optional[Dict[str, Any]] = None
    ) -> FilterResult:
        """
        过滤召回结果
        
        Args:
            query: 用户查询
            results: 召回结果列表
            user_context: 用户上下文
        
        Returns:
            FilterResult 过滤结果
        """
        start_time = time.perf_counter()
        
        if not results:
            return FilterResult(
                filtered_results=[],
                removed_count=0,
                reasons=[],
                duration_ms=0,
                total_count=0
            )
        
        # 获取用户角色
        user_context = user_context or {}
        user_role = user_context.get("role", "guest")
        user_id = user_context.get("user_id", "anonymous")
        user_level = self.ROLE_PERMISSIONS.get(user_role.lower(), 1)
        
        logger.debug(f"过滤召回结果：用户角色={user_role}, 权限级别={user_level}, 结果数={len(results)}")
        
        filtered = []
        removed_count = 0
        reasons = []
        
        for result in results:
            should_remove, reason = self._should_remove(result, user_level, user_context)
            
            if should_remove:
                removed_count += 1
                if reason and reason not in reasons:
                    reasons.append(reason)
                logger.debug(f"移除结果：id={result.get('id')}, 原因={reason}")
            else:
                filtered.append(result)
        
        duration_ms = int((time.perf_counter() - start_time) * 1000)
        
        filter_result = FilterResult(
            filtered_results=filtered,
            removed_count=removed_count,
            reasons=reasons,
            duration_ms=duration_ms,
            total_count=len(results)
        )
        
        logger.info(f"召回过滤完成：原始={len(results)}, 过滤后={len(filtered)}, 移除={removed_count}, {duration_ms}ms")
        
        return filter_result
    
    def _should_remove(
        self,
        result: Dict[str, Any],
        user_level: int,
        user_context: Dict[str, Any]
    ) -> tuple[bool, Optional[str]]:
        """
        判断是否应该移除某个结果
        
        Returns:
            (是否移除，原因)
        """
        # 1. 检查权限级别
        doc_permission = result.get("permission", "public")
        doc_level = self.PERMISSION_LEVELS.get(doc_permission.lower(), 1)
        
        if user_level < doc_level:
            return True, f"越权访问（需要 {doc_permission} 权限）"
        
        # 2. 检查文档访问列表（如果有）
        allowed_users = result.get("allowed_users", [])
        if allowed_users:
            user_id = user_context.get("user_id")
            if user_id and user_id not in allowed_users:
                return True, "不在允许访问列表中"
        
        # 3. 检查自定义过滤条件
        custom_filter = result.get("_filter", {})
        if custom_filter:
            # 检查订阅要求
            if custom_filter.get("require_subscription"):
                user_subscribed = user_context.get("is_subscribed", False)
                if not user_subscribed:
                    return True, "需要订阅"
            # 检查付费要求
            if custom_filter.get("require_payment"):
                user_paid = user_context.get("has_paid", False)
                if not user_paid:
                    return True, "需要付费"

        # 4. 检查敏感内容
        content = result.get("content", "")
        if self._contains_sensitive_content(content):
            return True, "敏感内容"
        
        return False, None


# 便捷函数
_filter_instance: Optional[RecallFilter] = None


def recall_filter(
    query: str,
    results: List[Dict[str, Any]],
    user_context: Optional[Dict[str, Any]] = None
) -> FilterResult:
    """
    召回过滤便捷函数
    
    Args:
        query: 用户查询
        results: 召回结果列表
        user_context: 用户上下文
    
    Returns:
        FilterResult 过滤结果
    """
    global _filter_instance
    if _filter_instance is None:
        _filter_instance = RecallFilter()
    
    with global_collector.measure("recall_filter"):
        return _filter_instance.filter(query, results, user_context)

