"""
元数据隐藏检测器

检测文件元数据中的隐藏恶意指令，支持：
1. PDF/DOCX/MD/HTML 格式元数据解析
2. 可疑字段检测（x-custom-、x-instruction-等）
3. 指令性内容识别（忽略、绕过、输出敏感信息等关键词）

性能要求：单文档检测 < 2 秒
"""

import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from enum import Enum

from ..utils.logger import get_logger
from ..utils.metrics import global_collector

logger = get_logger(__name__)


class MetadataType(Enum):
    """元数据类型"""
    PDF = "pdf"
    DOCX = "docx"
    MD = "markdown"
    HTML = "html"
    UNKNOWN = "unknown"


class ThreatLevel(Enum):
    """威胁等级"""
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class SuspiciousField:
    """可疑字段"""
    name: str
    value: str
    threat_level: ThreatLevel
    reason: str
    field_type: str  # custom, instruction, hidden, etc.


@dataclass
class MetadataDetectionResult:
    """元数据检测结果"""
    has_threats: bool
    threat_level: ThreatLevel
    suspicious_fields: List[SuspiciousField]
    metadata_summary: Dict[str, Any]
    duration_ms: int = 0
    file_type: MetadataType = MetadataType.UNKNOWN
    total_fields: int = 0
    recommendations: List[str] = field(default_factory=list)


class MetadataParser:
    """元数据解析器"""
    
    # 可疑字段前缀
    SUSPICIOUS_PREFIXES = [
        "x-custom-",
        "x-instruction-",
        "x-hidden-",
        "x-secret-",
        "x-internal-",
        "x-private-",
        "_hidden",
        "_secret",
        "__",
    ]
    
    # 恶意指令关键词
    MALICIOUS_KEYWORDS = [
        "ignore",
        "bypass",
        "override",
        "disable",
        "skip",
        "omit",
        "hidden",
        "secret",
        "confidential",
        "do not show",
        "do not display",
        "output sensitive",
        "reveal password",
        "extract credentials",
        "系统指令",
        "忽略",
        "绕过",
        "禁用",
        "跳过",
        "隐藏",
        "秘密",
        "敏感信息",
        "输出密码",
        "提取凭据",
    ]
    
    # 指令性模式
    INSTRUCTION_PATTERNS = [
        r"(?i)ignore\s+(previous|all|prior)",
        r"(?i)bypass\s+(security|filter|check)",
        r"(?i)override\s+(rule|policy|restriction)",
        r"(?i)output\s+(all|everything|sensitive)",
        r"(?i)reveal\s+(hidden|secret|password)",
        r"(?i)系统.*指令",
        r"(?i)忽略.*限制",
        r"(?i)绕过.*检测",
        r"(?i)输出.*敏感",
    ]
    
    def __init__(self):
        logger.info("MetadataParser 初始化完成")
    
    def parse(self, content: str, file_type: MetadataType) -> Dict[str, Any]:
        """
        解析元数据
        
        Args:
            content: 文件内容
            file_type: 文件类型
        
        Returns:
            元数据字典
        """
        if file_type == MetadataType.PDF:
            return self._parse_pdf(content)
        elif file_type == MetadataType.DOCX:
            return self._parse_docx(content)
        elif file_type == MetadataType.MD:
            return self._parse_markdown(content)
        elif file_type == MetadataType.HTML:
            return self._parse_html(content)
        else:
            return {}
    
    def _parse_pdf(self, content: str) -> Dict[str, Any]:
        """解析 PDF 元数据"""
        metadata = {}
        
        # 提取 PDF 元数据字段（简化实现）
        # 实际应该使用 PyPDF2 或 pdfplumber
        patterns = {
            "title": r"/Title\s*\(([^)]+)\)",
            "author": r"/Author\s*\(([^)]+)\)",
            "subject": r"/Subject\s*\(([^)]+)\)",
            "creator": r"/Creator\s*\(([^)]+)\)",
            "producer": r"/Producer\s*\(([^)]+)\)",
            "keywords": r"/Keywords\s*\(([^)]+)\)",
        }
        
        for field, pattern in patterns.items():
            match = re.search(pattern, content)
            if match:
                metadata[field] = match.group(1)
        
        # 提取自定义字段
        custom_pattern = r"/([xX]_?[\w-]+)\s*\(([^)]+)\)"
        for match in re.finditer(custom_pattern, content):
            field_name = match.group(1)
            field_value = match.group(2)
            metadata[field_name] = field_value
        
        return metadata
    
    def _parse_docx(self, content: str) -> Dict[str, Any]:
        """解析 DOCX 元数据"""
        metadata = {}
        
        # 提取 DOCX 核心属性（简化实现）
        # 实际应该使用 python-docx
        patterns = {
            "title": r"<dc:title[^>]*>([^<]+)</dc:title>",
            "creator": r"<dc:creator[^>]*>([^<]+)</dc:creator>",
            "description": r"<dc:description[^>]*>([^<]+)</dc:description>",
            "subject": r"<dc:subject[^>]*>([^<]+)</dc:subject>",
            "keywords": r"<cp:keywords[^>]*>([^<]+)</cp:keywords>",
        }
        
        for field, pattern in patterns.items():
            match = re.search(pattern, content)
            if match:
                metadata[field] = match.group(1)
        
        # 提取自定义属性
        custom_pattern = r'<vt:lpwstr[^>]*>([^<]+)</vt:lpwstr>'
        for match in re.finditer(custom_pattern, content):
            metadata[f"custom_{len(metadata)}"] = match.group(1)
        
        return metadata
    
    def _parse_markdown(self, content: str) -> Dict[str, Any]:
        """解析 Markdown 元数据（Front Matter）"""
        metadata = {}
        
        # 提取 YAML Front Matter
        front_matter_match = re.match(r'^---\s*\n(.*?)\n---\s*\n', content, re.DOTALL)
        if front_matter_match:
            front_matter = front_matter_match.group(1)
            # 简单的 YAML 解析
            for line in front_matter.split('\n'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    metadata[key.strip()] = value.strip()
        
        # 提取 HTML 注释中的隐藏内容
        comments = re.findall(r'<!--\s*(.*?)\s*-->', content, re.DOTALL)
        if comments:
            metadata["html_comments"] = comments
        
        # 提取隐藏字段
        hidden_pattern = r'\[//\]:\s*#\s*\((.*?)\)'
        hidden_matches = re.findall(hidden_pattern, content)
        if hidden_matches:
            metadata["hidden_fields"] = hidden_matches
        
        return metadata
    
    def _parse_html(self, content: str) -> Dict[str, Any]:
        """解析 HTML 元数据"""
        metadata = {}
        
        # 提取 meta 标签
        meta_pattern = r'<meta\s+([^>]+)>'
        for match in re.finditer(meta_pattern, content, re.IGNORECASE):
            attrs = match.group(1)
            name_match = re.search(r'name=["\']([^"\']+)["\']', attrs)
            content_match = re.search(r'content=["\']([^"\']+)["\']', attrs)
            
            if name_match and content_match:
                metadata[name_match.group(1)] = content_match.group(1)
        
        # 提取 title
        title_match = re.search(r'<title[^>]*>([^<]+)</title>', content, re.IGNORECASE)
        if title_match:
            metadata["title"] = title_match.group(1)
        
        # 提取注释
        comments = re.findall(r'<!--\s*(.*?)\s*-->', content, re.DOTALL)
        if comments:
            metadata["comments"] = comments
        
        # 提取 data 属性
        data_pattern = r'data-([\w-]+)\s*=\s*["\']([^"\']+)["\']'
        for match in re.finditer(data_pattern, content):
            metadata[f"data-{match.group(1)}"] = match.group(2)
        
        return metadata


class MetadataHiddenDetector:
    """元数据隐藏检测器"""
    
    def __init__(self):
        """初始化检测器"""
        self.parser = MetadataParser()
        
        # 编译正则
        self.instruction_patterns = [
            re.compile(p, re.IGNORECASE | re.DOTALL)
            for p in MetadataParser.INSTRUCTION_PATTERNS
        ]
        
        logger.info("MetadataHiddenDetector 初始化完成")
    
    def detect(
        self,
        content: str,
        file_type: Optional[MetadataType] = None,
        file_path: Optional[str] = None
    ) -> MetadataDetectionResult:
        """
        检测元数据中的隐藏威胁
        
        Args:
            content: 文件内容
            file_type: 文件类型（可选，自动检测）
            file_path: 文件路径（可选，用于类型推断）
        
        Returns:
            MetadataDetectionResult 检测结果
        """
        start_time = time.perf_counter()
        
        # 确定文件类型
        if file_type is None:
            file_type = self._detect_file_type(content, file_path)
        
        # 解析元数据
        metadata = self.parser.parse(content, file_type)
        
        # 检测可疑字段
        suspicious_fields = self._detect_suspicious_fields(metadata)
        
        # 检测恶意指令
        instruction_threats = self._detect_malicious_instructions(content, file_type)
        suspicious_fields.extend(instruction_threats)
        
        # 确定威胁等级
        threat_level = self._determine_threat_level(suspicious_fields)
        
        # 生成建议
        recommendations = self._generate_recommendations(suspicious_fields, threat_level)
        
        duration_ms = int((time.perf_counter() - start_time) * 1000)
        
        has_threats = len(suspicious_fields) > 0
        
        result = MetadataDetectionResult(
            has_threats=has_threats,
            threat_level=threat_level,
            suspicious_fields=suspicious_fields,
            metadata_summary={
                "total_fields": len(metadata),
                "field_names": list(metadata.keys())[:20],  # 限制数量
            },
            duration_ms=duration_ms,
            file_type=file_type,
            total_fields=len(metadata),
            recommendations=recommendations
        )
        
        logger.info(
            f"元数据检测完成：threats={has_threats}, "
            f"level={threat_level.value}, fields={len(suspicious_fields)}, {duration_ms}ms"
        )
        
        return result
    
    def _detect_file_type(self, content: str, file_path: Optional[str]) -> MetadataType:
        """检测文件类型"""
        if file_path:
            ext = Path(file_path).suffix.lower()
            if ext == ".pdf":
                return MetadataType.PDF
            elif ext in [".docx", ".doc"]:
                return MetadataType.DOCX
            elif ext == ".md":
                return MetadataType.MD
            elif ext in [".html", ".htm"]:
                return MetadataType.HTML
        
        # 根据内容推断
        if content.startswith("%PDF"):
            return MetadataType.PDF
        elif content.startswith("---") and "---" in content[:500]:
            return MetadataType.MD
        elif "<html" in content.lower() or "<!doctype html" in content.lower():
            return MetadataType.HTML
        elif "PK" in content[:2]:
            return MetadataType.DOCX
        
        return MetadataType.UNKNOWN
    
    def _detect_suspicious_fields(self, metadata: Dict[str, Any]) -> List[SuspiciousField]:
        """检测可疑字段"""
        suspicious = []
        
        for field_name, field_value in metadata.items():
            field_name_lower = field_name.lower()
            field_value_str = str(field_value)
            
            # 检查可疑前缀
            for prefix in MetadataParser.SUSPICIOUS_PREFIXES:
                if field_name_lower.startswith(prefix.lower()):
                    suspicious.append(SuspiciousField(
                        name=field_name,
                        value=field_value_str,
                        threat_level=ThreatLevel.MEDIUM,
                        reason=f"可疑字段前缀：{prefix}",
                        field_type="custom"
                    ))
                    break
            
            # 检查恶意关键词
            for keyword in MetadataParser.MALICIOUS_KEYWORDS:
                if keyword.lower() in field_value_str.lower():
                    suspicious.append(SuspiciousField(
                        name=field_name,
                        value=field_value_str,
                        threat_level=ThreatLevel.HIGH,
                        reason=f"包含恶意关键词：{keyword}",
                        field_type="instruction"
                    ))
                    break
        
        return suspicious
    
    def _detect_malicious_instructions(
        self,
        content: str,
        file_type: MetadataType
    ) -> List[SuspiciousField]:
        """检测恶意指令"""
        threats = []
        
        # 提取隐藏内容区域
        hidden_content = self._extract_hidden_content(content, file_type)
        
        # 检查指令模式
        for pattern in self.instruction_patterns:
            match = pattern.search(hidden_content)
            if match:
                threats.append(SuspiciousField(
                    name="hidden_instruction",
                    value=match.group(0)[:200],  # 限制长度
                    threat_level=ThreatLevel.CRITICAL,
                    reason=f"检测到指令模式：{pattern.pattern[:50]}",
                    field_type="instruction"
                ))
        
        return threats
    
    def _extract_hidden_content(self, content: str, file_type: MetadataType) -> str:
        """提取隐藏内容"""
        hidden_parts = []
        
        if file_type == MetadataType.PDF:
            # PDF 中的隐藏内容
            hidden_parts.extend(re.findall(r'/\w+\s*\(([^)]+)\)', content))
        
        elif file_type == MetadataType.MD:
            # Markdown 注释
            hidden_parts.extend(re.findall(r'<!--\s*(.*?)\s*-->', content, re.DOTALL))
            hidden_parts.extend(re.findall(r'\[//\]:\s*#\s*\((.*?)\)', content))
        
        elif file_type == MetadataType.HTML:
            # HTML 注释
            hidden_parts.extend(re.findall(r'<!--\s*(.*?)\s*-->', content, re.DOTALL))
            # 隐藏元素
            hidden_parts.extend(re.findall(r'display:\s*none[^;]*;([^<]+)', content))
        
        elif file_type == MetadataType.DOCX:
            # DOCX 中的隐藏文本
            hidden_parts.extend(re.findall(r'<w:vanish[^>]*>(.*?)</w:vanish>', content, re.DOTALL))
        
        return " ".join(hidden_parts)
    
    def _determine_threat_level(self, suspicious_fields: List[SuspiciousField]) -> ThreatLevel:
        """确定威胁等级"""
        if not suspicious_fields:
            return ThreatLevel.NONE
        
        # 有 CRITICAL 直接返回
        if any(f.threat_level == ThreatLevel.CRITICAL for f in suspicious_fields):
            return ThreatLevel.CRITICAL
        
        # 有 HIGH 返回 HIGH
        high_count = sum(1 for f in suspicious_fields if f.threat_level == ThreatLevel.HIGH)
        if high_count > 0:
            return ThreatLevel.HIGH
        
        # 有 MEDIUM 返回 MEDIUM
        medium_count = sum(1 for f in suspicious_fields if f.threat_level == ThreatLevel.MEDIUM)
        if medium_count > 2:
            return ThreatLevel.MEDIUM
        elif medium_count > 0:
            return ThreatLevel.LOW
        
        return ThreatLevel.LOW
    
    def _generate_recommendations(
        self,
        suspicious_fields: List[SuspiciousField],
        threat_level: ThreatLevel
    ) -> List[str]:
        """生成修复建议"""
        recommendations = []
        
        if threat_level == ThreatLevel.CRITICAL:
            recommendations.append("【严重】检测到恶意指令，建议立即隔离文件并深入调查")
        elif threat_level == ThreatLevel.HIGH:
            recommendations.append("【高危】检测到可疑指令，建议人工审核")
        elif threat_level == ThreatLevel.MEDIUM:
            recommendations.append("【中等】发现可疑元数据字段，建议检查来源")
        elif threat_level == ThreatLevel.LOW:
            recommendations.append("【低危】发现异常元数据，建议关注")
        
        # 分类建议
        field_types = {}
        for f in suspicious_fields:
            field_types[f.field_type] = field_types.get(f.field_type, 0) + 1
        
        if "instruction" in field_types:
            recommendations.append(f"发现{field_types['instruction']}个指令性内容，建议清除恶意指令")
        
        if "custom" in field_types:
            recommendations.append(f"发现{field_types['custom']}个自定义字段，建议核实用途")
        
        if not recommendations:
            recommendations.append("元数据正常，建议定期检测")
        
        return recommendations


# 便捷函数
_detector: Optional[MetadataHiddenDetector] = None


def detect_metadata_threats(
    content: str,
    file_type: Optional[MetadataType] = None,
    file_path: Optional[str] = None
) -> MetadataDetectionResult:
    """
    便捷检测函数
    
    Args:
        content: 文件内容
        file_type: 文件类型
        file_path: 文件路径
    
    Returns:
        MetadataDetectionResult 检测结果
    """
    global _detector
    if _detector is None:
        _detector = MetadataHiddenDetector()
    
    with global_collector.measure("metadata_detect"):
        return _detector.detect(content, file_type, file_path)


def detect_file(file_path: str) -> MetadataDetectionResult:
    """
    检测文件
    
    Args:
        file_path: 文件路径
    
    Returns:
        MetadataDetectionResult 检测结果
    """
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
    
    return detect_metadata_threats(content, file_path=file_path)
