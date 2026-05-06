"""
风险评分算法 v2

实现考虑组合效应的风险评分算法，支持：
1. 基础扣分（保持现有逻辑）
2. 组合系数计算（多种漏洞组合风险翻倍）
3. 攻击成本系数（低成本攻击更危险）
4. 影响范围系数（影响越大越危险）

性能要求：单次评分 < 50ms
"""

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple
from ..utils.logger import get_logger
from ..utils.metrics import global_collector

logger = get_logger(__name__)


class RiskLevel(Enum):
    """风险等级"""
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AttackCost(Enum):
    """攻击成本等级"""
    VERY_LOW = "very_low"      # 无需技术知识，工具现成
    LOW = "low"                # 基础技术知识，简单工具
    MEDIUM = "medium"          # 中等技术知识，需要定制
    HIGH = "high"              # 高级技术知识，复杂攻击
    VERY_HIGH = "very_high"    # 专家级，资源密集


class ImpactScope(Enum):
    """影响范围等级"""
    INDIVIDUAL = "individual"          # 单个用户
    GROUP = "group"                    # 用户组
    SYSTEM = "system"                  # 整个系统
    ORGANIZATION = "organization"      # 组织级别
    PUBLIC = "public"                  # 公开影响


@dataclass
class Vulnerability:
    """漏洞信息"""
    id: str
    name: str
    base_score: int  # 基础分数 0-100
    risk_level: RiskLevel
    attack_cost: AttackCost = AttackCost.MEDIUM
    impact_scope: ImpactScope = ImpactScope.INDIVIDUAL
    category: str = "general"  # 漏洞分类
    metadata: Dict = field(default_factory=dict)


@dataclass
class RiskScoreResult:
    """风险评分结果"""
    overall_score: int  # 0-100，分数越高风险越低
    risk_level: RiskLevel
    base_score: int  # 基础扣分后的分数
    combination_multiplier: float  # 组合系数
    attack_cost_factor: float  # 攻击成本系数
    impact_scope_factor: float  # 影响范围系数
    vulnerabilities: List[Vulnerability]
    vulnerability_count: int
    high_risk_count: int
    critical_combinations: List[str]  # 高危组合描述
    duration_ms: int = 0
    recommendations: List[str] = field(default_factory=list)


class RiskScorer:
    """风险评分器"""
    
    # 攻击成本系数（成本越低，系数越高，风险越大）
    ATTACK_COST_FACTORS = {
        AttackCost.VERY_LOW: 1.5,
        AttackCost.LOW: 1.3,
        AttackCost.MEDIUM: 1.0,
        AttackCost.HIGH: 0.8,
        AttackCost.VERY_HIGH: 0.6,
    }
    
    # 影响范围系数（影响越大，系数越高）
    IMPACT_SCOPE_FACTORS = {
        ImpactScope.INDIVIDUAL: 1.0,
        ImpactScope.GROUP: 1.2,
        ImpactScope.SYSTEM: 1.5,
        ImpactScope.ORGANIZATION: 1.8,
        ImpactScope.PUBLIC: 2.0,
    }
    
    # 风险等级权重
    RISK_LEVEL_WEIGHTS = {
        RiskLevel.NONE: 0,
        RiskLevel.LOW: 1,
        RiskLevel.MEDIUM: 2,
        RiskLevel.HIGH: 3,
        RiskLevel.CRITICAL: 4,
    }
    
    # 高危组合规则（漏洞类别组合会触发额外风险）
    DANGEROUS_COMBINATIONS = [
        {"categories": {"injection", "data_exfiltration"}, "multiplier": 2.0, "desc": "注入 + 数据外泄组合"},
        {"categories": {"jailbreak", "privilege_escalation"}, "multiplier": 1.8, "desc": "越狱 + 权限提升组合"},
        {"categories": {"prompt_injection", "context_poisoning"}, "multiplier": 1.7, "desc": "提示词注入 + 上下文投毒组合"},
        {"categories": {"injection", "jailbreak"}, "multiplier": 1.6, "desc": "注入 + 越狱组合"},
        {"categories": {"data_exfiltration", "privacy_violation"}, "multiplier": 1.5, "desc": "数据外泄 + 隐私侵犯组合"},
    ]
    
    def __init__(self):
        """初始化评分器"""
        logger.info("RiskScorer v2 初始化完成")
    
    def score(
        self,
        vulnerabilities: List[Vulnerability],
        context: Optional[Dict] = None
    ) -> RiskScoreResult:
        """
        计算风险评分
        
        Args:
            vulnerabilities: 漏洞列表
            context: 上下文信息（可选）
        
        Returns:
            RiskScoreResult 评分结果
        """
        start_time = time.perf_counter()
        
        if not vulnerabilities:
            # 无漏洞，安全
            return RiskScoreResult(
                overall_score=100,
                risk_level=RiskLevel.NONE,
                base_score=100,
                combination_multiplier=1.0,
                attack_cost_factor=1.0,
                impact_scope_factor=1.0,
                vulnerabilities=[],
                vulnerability_count=0,
                high_risk_count=0,
                critical_combinations=[],
                duration_ms=0,
                recommendations=["系统当前无检测到漏洞"]
            )
        
        # 1. 计算基础扣分
        base_score = self._calculate_base_score(vulnerabilities)
        
        # 2. 计算组合系数
        combination_multiplier, critical_combos = self._calculate_combination_multiplier(vulnerabilities)
        
        # 3. 计算攻击成本系数
        attack_cost_factor = self._calculate_attack_cost_factor(vulnerabilities)
        
        # 4. 计算影响范围系数
        impact_scope_factor = self._calculate_impact_scope_factor(vulnerabilities)
        
        # 5. 计算最终分数
        # 公式：overall = base_score / (combination * attack_cost * impact_scope)
        total_multiplier = combination_multiplier * attack_cost_factor * impact_scope_factor
        overall_score = max(0, min(100, int(base_score / total_multiplier)))
        
        # 6. 确定风险等级
        risk_level = self._determine_risk_level(overall_score, vulnerabilities)
        
        # 7. 统计信息
        high_risk_count = sum(1 for v in vulnerabilities if v.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL])
        
        # 8. 生成建议
        recommendations = self._generate_recommendations(
            vulnerabilities, 
            critical_combos,
            risk_level
        )
        
        duration_ms = int((time.perf_counter() - start_time) * 1000)
        
        result = RiskScoreResult(
            overall_score=overall_score,
            risk_level=risk_level,
            base_score=base_score,
            combination_multiplier=combination_multiplier,
            attack_cost_factor=attack_cost_factor,
            impact_scope_factor=impact_scope_factor,
            vulnerabilities=vulnerabilities,
            vulnerability_count=len(vulnerabilities),
            high_risk_count=high_risk_count,
            critical_combinations=critical_combos,
            duration_ms=duration_ms,
            recommendations=recommendations
        )
        
        logger.info(
            f"风险评分完成：score={overall_score}, level={risk_level.value}, "
            f"vulns={len(vulnerabilities)}, high_risk={high_risk_count}, {duration_ms}ms"
        )
        
        return result
    
    def _calculate_base_score(self, vulnerabilities: List[Vulnerability]) -> int:
        """
        计算基础扣分
        
        每个漏洞根据风险等级扣分：
        - CRITICAL: 扣 40 分
        - HIGH: 扣 25 分
        - MEDIUM: 扣 15 分
        - LOW: 扣 5 分
        """
        score = 100
        deductions = {
            RiskLevel.CRITICAL: 40,
            RiskLevel.HIGH: 25,
            RiskLevel.MEDIUM: 15,
            RiskLevel.LOW: 5,
            RiskLevel.NONE: 0,
        }
        
        for vuln in vulnerabilities:
            deduction = deductions.get(vuln.risk_level, 0)
            score -= deduction
        
        return max(0, score)
    
    def _calculate_combination_multiplier(
        self, 
        vulnerabilities: List[Vulnerability]
    ) -> Tuple[float, List[str]]:
        """
        计算组合系数
        
        多种漏洞组合会导致风险翻倍。
        检查预定义的危险组合规则。
        
        Returns:
            (multiplier, critical_combinations_descriptions)
        """
        if len(vulnerabilities) < 2:
            return 1.0, []
        
        # 收集所有漏洞类别
        categories: Set[str] = {v.category for v in vulnerabilities}
        
        multiplier = 1.0
        critical_combos = []
        
        for combo_rule in self.DANGEROUS_COMBINATIONS:
            required_categories = combo_rule["categories"]
            if required_categories.issubset(categories):
                multiplier = max(multiplier, combo_rule["multiplier"])
                critical_combos.append(combo_rule["desc"])
        
        # 如果漏洞数量很多，额外增加系数
        if len(vulnerabilities) >= 5:
            multiplier = max(multiplier, 1.5)
            if len(vulnerabilities) >= 5:
                critical_combos.append(f"检测到{len(vulnerabilities)}个漏洞，多重风险叠加")
        
        return multiplier, critical_combos
    
    def _calculate_attack_cost_factor(self, vulnerabilities: List[Vulnerability]) -> float:
        """
        计算攻击成本系数
        
        取所有漏洞中攻击成本最低的（最危险的）作为代表。
        """
        if not vulnerabilities:
            return 1.0
        
        # 找到攻击成本最低的漏洞（最危险）
        min_cost = min(
            vulnerabilities,
            key=lambda v: list(self.ATTACK_COST_FACTORS.keys()).index(v.attack_cost)
        ).attack_cost
        
        return self.ATTACK_COST_FACTORS.get(min_cost, 1.0)
    
    def _calculate_impact_scope_factor(self, vulnerabilities: List[Vulnerability]) -> float:
        """
        计算影响范围系数
        
        取所有漏洞中影响范围最大的作为代表。
        """
        if not vulnerabilities:
            return 1.0
        
        # 找到影响范围最大的漏洞
        max_impact = max(
            vulnerabilities,
            key=lambda v: list(self.IMPACT_SCOPE_FACTORS.keys()).index(v.impact_scope)
        ).impact_scope
        
        return self.IMPACT_SCOPE_FACTORS.get(max_impact, 1.0)
    
    def _determine_risk_level(
        self, 
        overall_score: int, 
        vulnerabilities: List[Vulnerability]
    ) -> RiskLevel:
        """
        根据分数和漏洞情况确定风险等级
        
        分数越低，风险等级越高。
        """
        # 有 CRITICAL 漏洞直接定为 CRITICAL
        if any(v.risk_level == RiskLevel.CRITICAL for v in vulnerabilities):
            return RiskLevel.CRITICAL
        
        # 根据分数判断
        if overall_score >= 80:
            return RiskLevel.LOW
        elif overall_score >= 60:
            return RiskLevel.MEDIUM
        elif overall_score >= 40:
            return RiskLevel.HIGH
        else:
            return RiskLevel.CRITICAL
    
    def _generate_recommendations(
        self,
        vulnerabilities: List[Vulnerability],
        critical_combos: List[str],
        risk_level: RiskLevel
    ) -> List[str]:
        """生成修复建议"""
        recommendations = []
        
        if risk_level == RiskLevel.CRITICAL:
            recommendations.append("【紧急】检测到严重风险，建议立即停止相关服务并修复")
        elif risk_level == RiskLevel.HIGH:
            recommendations.append("【高危】检测到高风险漏洞，建议优先修复")
        
        # 针对高危组合的建议
        if critical_combos:
            recommendations.append(f"检测到{len(critical_combos)}个危险组合：{', '.join(critical_combos)}")
            recommendations.append("建议优先修复组合中的核心漏洞以切断攻击链")
        
        # 针对攻击成本低的建议
        low_cost_vulns = [v for v in vulnerabilities if v.attack_cost in [AttackCost.VERY_LOW, AttackCost.LOW]]
        if low_cost_vulns:
            recommendations.append(f"发现{len(low_cost_vulns)}个易利用漏洞，攻击门槛低，建议优先修复")
        
        # 针对影响范围大的建议
        wide_impact_vulns = [v for v in vulnerabilities if v.impact_scope in [ImpactScope.SYSTEM, ImpactScope.ORGANIZATION, ImpactScope.PUBLIC]]
        if wide_impact_vulns:
            recommendations.append(f"发现{len(wide_impact_vulns)}个影响范围大的漏洞，可能影响系统/组织安全")
        
        # 分类别建议
        categories = {}
        for v in vulnerabilities:
            if v.category not in categories:
                categories[v.category] = 0
            categories[v.category] += 1
        
        for category, count in categories.items():
            recommendations.append(f"{category}类漏洞{count}个，建议系统性排查和修复")
        
        if not recommendations:
            recommendations.append("当前风险可控，建议定期扫描和更新")
        
        return recommendations


# 便捷函数
_scorer_instance: Optional[RiskScorer] = None


def risk_score(
    vulnerabilities: List[Vulnerability],
    context: Optional[Dict] = None
) -> RiskScoreResult:
    """
    风险评分便捷函数
    
    Args:
        vulnerabilities: 漏洞列表
        context: 上下文信息
    
    Returns:
        RiskScoreResult 评分结果
    """
    global _scorer_instance
    if _scorer_instance is None:
        _scorer_instance = RiskScorer()
    
    with global_collector.measure("risk_score"):
        return _scorer_instance.score(vulnerabilities, context)


def calculate_risk_from_issues(
    issues: List[Dict],
    context: Optional[Dict] = None
) -> RiskScoreResult:
    """
    从检测结果直接计算风险评分
    
    适配现有检测器的输出格式。
    
    Args:
        issues: 问题列表（来自检测器）
               每个问题包含：level, category, description 等
        context: 上下文信息
    
    Returns:
        RiskScoreResult 评分结果
    """
    # 映射风险等级
    level_map = {
        "critical": RiskLevel.CRITICAL,
        "high": RiskLevel.HIGH,
        "medium": RiskLevel.MEDIUM,
        "low": RiskLevel.LOW,
    }
    
    vulnerabilities = []
    for i, issue in enumerate(issues):
        level_str = issue.get("level", "low")
        category = issue.get("category", "general")
        
        # 根据问题类型推断攻击成本和影响范围
        attack_cost = AttackCost.MEDIUM
        impact_scope = ImpactScope.INDIVIDUAL
        
        if "injection" in category.lower():
            attack_cost = AttackCost.LOW
            impact_scope = ImpactScope.SYSTEM
        elif "data" in category.lower() or "exfiltration" in category.lower():
            impact_scope = ImpactScope.ORGANIZATION
        elif "privilege" in category.lower() or "escalation" in category.lower():
            attack_cost = AttackCost.MEDIUM
            impact_scope = ImpactScope.SYSTEM
        
        vuln = Vulnerability(
            id=f"issue_{i}",
            name=issue.get("description", "Unknown Issue"),
            base_score=80 if level_str == "high" else 50,
            risk_level=level_map.get(level_str, RiskLevel.LOW),
            attack_cost=attack_cost,
            impact_scope=impact_scope,
            category=category,
            metadata=issue
        )
        vulnerabilities.append(vuln)
    
    return risk_score(vulnerabilities, context)
