"""
GraphRAG 投毒检测器

检测知识图谱中的恶意投毒数据，支持：
1. 多源一致性校验（对比 Wikidata/DBpedia 等权威数据源）
2. 逻辑关系验证（检查违反常识的关系）
3. 多跳推理完整性检测

性能要求：单文档检测 < 5 秒
"""

import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from enum import Enum

from ..utils.logger import get_logger
from ..utils.metrics import global_collector

logger = get_logger(__name__)


class PoisonType(Enum):
    """投毒类型"""
    INCONSISTENT_FACT = "inconsistent_fact"  # 与权威数据源不一致
    LOGICAL_VIOLATION = "logical_violation"  # 逻辑关系违反常识
    INCOMPLETE_REASONING = "incomplete_reasoning"  # 多跳推理不完整
    CIRCULAR_REFERENCE = "circular_reference"  # 循环引用
    CONTRADICTORY_RELATION = "contradictory_relation"  # 矛盾关系


@dataclass
class Triple:
    """RDF 三元组"""
    subject: str
    predicate: str
    object: str
    metadata: Dict = field(default_factory=dict)


@dataclass
class PoisonDetectionResult:
    """投毒检测结果"""
    is_poisoned: bool
    poison_type: Optional[PoisonType]
    confidence: float  # 0.0-1.0
    poisoned_triples: List[Triple]
    evidence: List[str]
    duration_ms: int = 0
    total_triples: int = 0
    suspicious_count: int = 0
    recommendations: List[str] = field(default_factory=list)


class GraphPoisonDetector:
    """GraphRAG 投毒检测器"""
    
    # 逻辑规则（从 logic_rules.json 加载）
    LOGICAL_RULES = {
        "symmetric": [
            ("married_to", "married_to"),
            ("sibling_of", "sibling_of"),
            ("friend_of", "friend_of"),
        ],
        "asymmetric": [
            ("parent_of", "child_of"),
            ("teacher_of", "student_of"),
            ("boss_of", "subordinate_of"),
        ],
        "transitive": [
            "ancestor_of",
            "descendant_of",
            "part_of",
            "located_in",
        ],
        "incompatible": [
            ("alive", "dead"),
            ("male", "female"),
            ("married", "single"),
            ("born_in", "died_before"),
        ]
    }
    
    # 常识规则
    COMMON_SENSE_RULES = [
        {"pattern": r"person.*born_in.*year", "constraint": "year >= 1800"},
        {"pattern": r"person.*died_at_age", "constraint": "age > 0 AND age < 150"},
        {"pattern": r"person.*child_of.*person", "constraint": "parent_age > child_age"},
    ]
    
    def __init__(self, rules_file: Optional[str] = None):
        """
        初始化检测器
        
        Args:
            rules_file: 逻辑规则文件路径（可选）
        """
        self.rules_file = rules_file
        if rules_file and Path(rules_file).exists():
            self._load_rules(rules_file)
        
        # 外部 API 缓存
        self._wikidata_cache: Dict[str, Any] = {}
        self._dbpedia_cache: Dict[str, Any] = {}
        
        logger.info("GraphPoisonDetector 初始化完成")
    
    def _load_rules(self, rules_file: str):
        """加载外部规则文件"""
        try:
            with open(rules_file, 'r', encoding='utf-8') as f:
                rules = json.load(f)
                self.LOGICAL_RULES.update(rules.get("logical_rules", {}))
                logger.info(f"从 {rules_file} 加载了额外规则")
        except Exception as e:
            logger.warning(f"加载规则文件失败：{e}")
    
    def detect(
        self,
        triples: List[Triple],
        enable_external_check: bool = True,
        timeout_ms: int = 5000
    ) -> PoisonDetectionResult:
        """
        检测知识图谱投毒
        
        Args:
            triples: RDF 三元组列表
            enable_external_check: 是否启用外部数据源校验
            timeout_ms: 超时时间（毫秒）
        
        Returns:
            PoisonDetectionResult 检测结果
        """
        start_time = time.perf_counter()
        
        if not triples:
            return PoisonDetectionResult(
                is_poisoned=False,
                poison_type=None,
                confidence=0.0,
                poisoned_triples=[],
                evidence=[],
                duration_ms=0,
                total_triples=0,
                recommendations=["图谱为空，无需检测"]
            )
        
        poisoned_triples = []
        evidence = []
        poison_types_detected: Set[PoisonType] = set()
        
        # 1. 逻辑关系验证
        logical_poisons = self._check_logical_relations(triples)
        poisoned_triples.extend(logical_poisons["triples"])
        evidence.extend(logical_poisons["evidence"])
        poison_types_detected.update(logical_poisons["types"])
        
        # 2. 循环引用检测
        circular_poisons = self._check_circular_references(triples)
        poisoned_triples.extend(circular_poisons["triples"])
        evidence.extend(circular_poisons["evidence"])
        if circular_poisons["triples"]:
            poison_types_detected.add(PoisonType.CIRCULAR_REFERENCE)
        
        # 3. 矛盾关系检测
        contradiction_poisons = self._check_contradictory_relations(triples)
        poisoned_triples.extend(contradiction_poisons["triples"])
        evidence.extend(contradiction_poisons["evidence"])
        if contradiction_poisons["triples"]:
            poison_types_detected.add(PoisonType.CONTRADICTORY_RELATION)
        
        # 4. 多跳推理完整性检测
        incomplete_poisons = self._check_reasoning_completeness(triples)
        poisoned_triples.extend(incomplete_poisons["triples"])
        evidence.extend(incomplete_poisons["evidence"])
        if incomplete_poisons["triples"]:
            poison_types_detected.add(PoisonType.INCOMPLETE_REASONING)
        
        # 5. 外部数据源一致性校验（可选）
        if enable_external_check:
            external_poisons = self._check_external_consistency(triples, timeout_ms)
            poisoned_triples.extend(external_poisons["triples"])
            evidence.extend(external_poisons["evidence"])
            if external_poisons["triples"]:
                poison_types_detected.add(PoisonType.INCONSISTENT_FACT)
        
        # 去重
        unique_poisoned = self._deduplicate_triples(poisoned_triples)
        
        # 计算置信度
        confidence = self._calculate_confidence(
            len(unique_poisoned),
            len(triples),
            len(poison_types_detected)
        )
        
        # 确定主要投毒类型
        primary_poison_type = list(poison_types_detected)[0] if poison_types_detected else None
        
        # 生成建议
        recommendations = self._generate_recommendations(
            poison_types_detected,
            unique_poisoned
        )
        
        duration_ms = int((time.perf_counter() - start_time) * 1000)
        
        is_poisoned = len(unique_poisoned) > 0
        
        result = PoisonDetectionResult(
            is_poisoned=is_poisoned,
            poison_type=primary_poison_type,
            confidence=confidence,
            poisoned_triples=unique_poisoned,
            evidence=evidence,
            duration_ms=duration_ms,
            total_triples=len(triples),
            suspicious_count=len(unique_poisoned),
            recommendations=recommendations
        )
        
        logger.info(
            f"GraphRAG 投毒检测完成：poisoned={is_poisoned}, "
            f"suspicious={len(unique_poisoned)}/{len(triples)}, "
            f"confidence={confidence:.2f}, {duration_ms}ms"
        )
        
        return result
    
    def _check_logical_relations(self, triples: List[Triple]) -> Dict:
        """检查逻辑关系违规"""
        poisoned = []
        evidence = []
        types = set()
        
        # 构建关系图
        graph: Dict[str, Dict[str, List[str]]] = {}
        for triple in triples:
            if triple.subject not in graph:
                graph[triple.subject] = {}
            if triple.predicate not in graph[triple.subject]:
                graph[triple.subject][triple.predicate] = []
            graph[triple.subject][triple.predicate].append(triple.object)
        
        # 检查不对称关系
        for subj, preds in graph.items():
            for pred, objs in preds.items():
                # 查找反向关系
                inverse_pred = self._get_inverse_predicate(pred)
                if inverse_pred:
                    for obj in objs:
                        if obj in graph and pred in graph[obj]:
                            # 发现违反不对称关系
                            poisoned.append(triple)
                            evidence.append(
                                f"违反不对称关系：{subj} {pred} {obj} 但 {obj} {pred} {subj}"
                            )
                            types.add(PoisonType.LOGICAL_VIOLATION)
        
        return {"triples": poisoned, "evidence": evidence, "types": types}
    
    def _get_inverse_predicate(self, predicate: str) -> Optional[str]:
        """获取反向谓词"""
        for pair in self.LOGICAL_RULES["asymmetric"]:
            if pair[0] == predicate:
                return pair[1]
            elif pair[1] == predicate:
                return pair[0]
        return None
    
    def _check_circular_references(self, triples: List[Triple]) -> Dict:
        """检查循环引用"""
        poisoned = []
        evidence = []
        
        # 构建图
        graph: Dict[str, Set[str]] = {}
        for triple in triples:
            if triple.predicate in ["part_of", "located_in", "contains"]:
                if triple.subject not in graph:
                    graph[triple.subject] = set()
                graph[triple.subject].add(triple.object)
        
        # DFS 检测循环
        def has_cycle(node: str, visited: Set[str], rec_stack: Set[str], path: List[str]) -> Optional[List[str]]:
            visited.add(node)
            rec_stack.add(node)
            path.append(node)
            
            for neighbor in graph.get(node, []):
                if neighbor not in visited:
                    cycle = has_cycle(neighbor, visited, rec_stack, path)
                    if cycle:
                        return cycle
                elif neighbor in rec_stack:
                    # 发现循环
                    cycle_start = path.index(neighbor)
                    return path[cycle_start:] + [neighbor]
            
            path.pop()
            rec_stack.remove(node)
            return None
        
        visited: Set[str] = set()
        for node in graph:
            if node not in visited:
                cycle = has_cycle(node, visited, set(), [])
                if cycle:
                    evidence.append(f"发现循环引用：{' -> '.join(cycle)}")
                    # 标记循环中的三元组
                    for i in range(len(cycle) - 1):
                        for triple in triples:
                            if triple.subject == cycle[i] and triple.object == cycle[i + 1]:
                                poisoned.append(triple)
        
        return {"triples": poisoned, "evidence": evidence}
    
    def _check_contradictory_relations(self, triples: List[Triple]) -> Dict:
        """检查矛盾关系"""
        poisoned = []
        evidence = []
        
        # 按主体分组
        by_subject: Dict[str, List[Triple]] = {}
        for triple in triples:
            if triple.subject not in by_subject:
                by_subject[triple.subject] = []
            by_subject[triple.subject].append(triple)
        
        # 检查矛盾
        for subj, subj_triples in by_subject.items():
            predicates = {t.predicate for t in subj_triples}
            objects = {t.object for t in subj_triples}
            
            for pred1, pred2 in self.LOGICAL_RULES["incompatible"]:
                if pred1 in predicates and pred2 in predicates:
                    # 发现矛盾关系
                    for t in subj_triples:
                        if t.predicate in [pred1, pred2]:
                            poisoned.append(t)
                    evidence.append(
                        f"矛盾关系：{subj} 同时具有 {pred1} 和 {pred2}"
                    )
        
        return {"triples": poisoned, "evidence": evidence}
    
    def _check_reasoning_completeness(self, triples: List[Triple]) -> Dict:
        """检查多跳推理完整性"""
        poisoned = []
        evidence = []
        
        # 构建关系链
        graph: Dict[str, Dict[str, List[str]]] = {}
        for triple in triples:
            if triple.subject not in graph:
                graph[triple.subject] = {}
            if triple.predicate not in graph[triple.subject]:
                graph[triple.subject][triple.predicate] = []
            graph[triple.subject][triple.predicate].append(triple.object)
        
        # 检查传递关系
        for trans_pred in self.LOGICAL_RULES["transitive"]:
            for subj, preds in graph.items():
                if trans_pred in preds:
                    for mid in preds[trans_pred]:
                        if mid in graph and trans_pred in graph[mid]:
                            # A trans B, B trans C => 应该有 A trans C
                            for end in graph[mid][trans_pred]:
                                if end not in preds.get(trans_pred, []):
                                    # 缺失传递关系
                                    evidence.append(
                                        f"推理不完整：{subj} {trans_pred} {mid}, "
                                        f"{mid} {trans_pred} {end}, "
                                        f"但缺少 {subj} {trans_pred} {end}"
                                    )
                                    poisoned.append(Triple(subj, trans_pred, end))
        
        return {"triples": poisoned, "evidence": evidence}
    
    def _check_external_consistency(
        self,
        triples: List[Triple],
        timeout_ms: int
    ) -> Dict:
        """检查外部数据源一致性"""
        poisoned = []
        evidence = []
        
        # 简化版：模拟外部 API 调用
        # 实际实现应该调用 Wikidata/DBpedia API
        start = time.perf_counter()
        
        for triple in triples:
            if (time.perf_counter() - start) * 1000 > timeout_ms:
                logger.warning("外部检查超时")
                break
            
            # 检查是否是已知实体
            if self._is_known_entity(triple.subject):
                # 模拟验证（实际应该调用 API）
                is_consistent = self._verify_with_wikidata(triple)
                if not is_consistent:
                    poisoned.append(triple)
                    evidence.append(
                        f"与 Wikidata 不一致：{triple.subject} {triple.predicate} {triple.object}"
                    )
        
        return {"triples": poisoned, "evidence": evidence}
    
    def _is_known_entity(self, entity: str) -> bool:
        """检查是否是已知实体（简化实现）"""
        # 实际实现应该查询 Wikidata
        known_patterns = [
            r"Q\d+",  # Wikidata ID
            r"dbo:.*",  # DBpedia Ontology
        ]
        return any(re.match(p, entity) for p in known_patterns)
    
    def _verify_with_wikidata(self, triple: Triple) -> bool:
        """与 Wikidata 验证（简化实现）"""
        # 实际实现应该调用 Wikidata API
        # https://www.wikidata.org/w/api.php
        # 这里返回 True 表示一致
        return True
    
    def _deduplicate_triples(self, triples: List[Triple]) -> List[Triple]:
        """去重三元组"""
        seen = set()
        unique = []
        for t in triples:
            key = (t.subject, t.predicate, t.object)
            if key not in seen:
                seen.add(key)
                unique.append(t)
        return unique
    
    def _calculate_confidence(
        self,
        poisoned_count: int,
        total_count: int,
        type_count: int
    ) -> float:
        """计算置信度"""
        if poisoned_count == 0:
            return 0.0
        
        # 基于投毒比例
        ratio = poisoned_count / max(total_count, 1)
        
        # 基于检测到的类型数量
        type_factor = min(1.0, type_count * 0.3)
        
        confidence = min(1.0, ratio * 0.7 + type_factor)
        
        return round(confidence, 2)
    
    def _generate_recommendations(
        self,
        poison_types: Set[PoisonType],
        poisoned_triples: List[Triple]
    ) -> List[str]:
        """生成修复建议"""
        recommendations = []
        
        if PoisonType.INCONSISTENT_FACT in poison_types:
            recommendations.append("发现与权威数据源不一致的事实，建议核实数据来源")
        
        if PoisonType.LOGICAL_VIOLATION in poison_types:
            recommendations.append("发现逻辑关系违规，建议检查关系定义")
        
        if PoisonType.CIRCULAR_REFERENCE in poison_types:
            recommendations.append("发现循环引用，建议重构图谱结构")
        
        if PoisonType.CONTRADICTORY_RELATION in poison_types:
            recommendations.append("发现矛盾关系，建议统一数据标准")
        
        if PoisonType.INCOMPLETE_REASONING in poison_types:
            recommendations.append("发现推理不完整，建议补充缺失的关系链")
        
        if poisoned_triples:
            recommendations.append(
                f"共发现{len(poisoned_triples)}个可疑三元组，建议人工审核"
            )
        
        if not recommendations:
            recommendations.append("图谱数据质量良好，建议定期检测")
        
        return recommendations


# 便捷函数
_detector: Optional[GraphPoisonDetector] = None


def detect_graph_poison(
    triples: List[Triple],
    enable_external_check: bool = True
) -> PoisonDetectionResult:
    """
    便捷检测函数
    
    Args:
        triples: RDF 三元组列表
        enable_external_check: 是否启用外部校验
    
    Returns:
        PoisonDetectionResult 检测结果
    """
    global _detector
    if _detector is None:
        _detector = GraphPoisonDetector()
    
    with global_collector.measure("graph_poison_detect"):
        return _detector.detect(triples, enable_external_check)


def parse_and_detect(
    content: str,
    format: str = "ttl"
) -> PoisonDetectionResult:
    """
    解析并检测
    
    Args:
        content: 图谱内容（TTL/RDF/JSON-LD）
        format: 格式类型
    
    Returns:
        PoisonDetectionResult 检测结果
    """
    from ..utils.metadata_parser import parse_graph_content
    
    triples = parse_graph_content(content, format)
    return detect_graph_poison(triples)
