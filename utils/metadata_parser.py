"""
元数据解析工具

支持多种格式的元数据解析和图谱内容解析。
"""

import json
import re
from typing import Any, Dict, List, Optional
from pathlib import Path

from ..utils.logger import get_logger
from ..detectors.graph_poison import Triple

logger = get_logger(__name__)


def parse_graph_content(content: str, format: str = "ttl") -> List[Triple]:
    """
    解析图谱内容为三元组
    
    Args:
        content: 图谱内容
        format: 格式类型 (ttl, rdf, json-ld)
    
    Returns:
        三元组列表
    """
    if format == "ttl":
        return parse_turtle(content)
    elif format == "rdf":
        return parse_rdf(content)
    elif format == "json-ld":
        return parse_jsonld(content)
    else:
        logger.warning(f"不支持的图谱格式：{format}")
        return []


def parse_turtle(content: str) -> List[Triple]:
    """解析 Turtle 格式"""
    triples = []
    
    # 简单的 Turtle 解析
    # 格式：subject predicate object .
    pattern = r'(\S+)\s+(\S+)\s+([^\.]+)\s*\.'
    
    for match in re.finditer(pattern, content):
        subject = match.group(1).strip()
        predicate = match.group(2).strip()
        obj = match.group(3).strip()
        
        # 清理引号
        obj = obj.strip('"\'')
        
        triples.append(Triple(
            subject=subject,
            predicate=predicate,
            object=obj
        ))
    
    logger.info(f"解析 Turtle 格式：{len(triples)}个三元组")
    return triples


def parse_rdf(content: str) -> List[Triple]:
    """解析 RDF/XML 格式"""
    triples = []
    
    # 提取 RDF 三元组
    # 格式：<subject> <predicate> <object> .
    pattern = r'<([^>]+)>\s+<([^>]+)>\s+<([^>]+)>\s*\.'
    
    for match in re.finditer(pattern, content):
        triples.append(Triple(
            subject=match.group(1),
            predicate=match.group(2),
            object=match.group(3)
        ))
    
    # 也处理带字面量的情况
    literal_pattern = r'<([^>]+)>\s+<([^>]+)>\s+"([^"]+)"'
    for match in re.finditer(literal_pattern, content):
        triples.append(Triple(
            subject=match.group(1),
            predicate=match.group(2),
            object=match.group(3)
        ))
    
    logger.info(f"解析 RDF/XML 格式：{len(triples)}个三元组")
    return triples


def parse_jsonld(content: str) -> List[Triple]:
    """解析 JSON-LD 格式"""
    triples = []
    
    try:
        data = json.loads(content)
        
        # 处理 @graph
        if "@graph" in data:
            items = data["@graph"]
        elif isinstance(data, list):
            items = data
        else:
            items = [data]
        
        for item in items:
            subject = item.get("@id", "")
            
            for predicate, obj in item.items():
                if predicate.startswith("@"):
                    continue
                
                if isinstance(obj, list):
                    for o in obj:
                        if isinstance(o, dict):
                            obj_val = o.get("@id", o.get("@value", str(o)))
                        else:
                            obj_val = str(o)
                        triples.append(Triple(subject, predicate, obj_val))
                elif isinstance(obj, dict):
                    obj_val = obj.get("@id", obj.get("@value", str(obj)))
                    triples.append(Triple(subject, predicate, obj_val))
                else:
                    triples.append(Triple(subject, predicate, str(obj)))
    
    except json.JSONDecodeError as e:
        logger.error(f"JSON-LD 解析失败：{e}")
    
    logger.info(f"解析 JSON-LD 格式：{len(triples)}个三元组")
    return triples


def extract_metadata_pdf(content: str) -> Dict[str, Any]:
    """
    提取 PDF 元数据
    
    Args:
        content: PDF 文件内容（二进制或文本）
    
    Returns:
        元数据字典
    """
    metadata = {}
    
    # 尝试提取文本元数据
    patterns = {
        "title": r"/Title\s*\(([^)]+)\)",
        "author": r"/Author\s*\(([^)]+)\)",
        "subject": r"/Subject\s*\(([^)]+)\)",
        "creator": r"/Creator\s*\(([^)]+)\)",
        "producer": r"/Producer\s*\(([^)]+)\)",
        "keywords": r"/Keywords\s*\(([^)]+)\)",
        "creation_date": r"/CreationDate\s*\(([^)]+)\)",
        "mod_date": r"/ModDate\s*\(([^)]+)\)",
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


def extract_metadata_docx(content: str) -> Dict[str, Any]:
    """
    提取 DOCX 元数据
    
    Args:
        content: DOCX 文件内容（XML 文本）
    
    Returns:
        元数据字典
    """
    metadata = {}
    
    patterns = {
        "title": r"<dc:title[^>]*>([^<]+)</dc:title>",
        "creator": r"<dc:creator[^>]*>([^<]+)</dc:creator>",
        "description": r"<dc:description[^>]*>([^<]+)</dc:description>",
        "subject": r"<dc:subject[^>]*>([^<]+)</dc:subject>",
        "keywords": r"<cp:keywords[^>]*>([^<]+)</cp:keywords>",
        "created": r"<dcterms:created[^>]*>([^<]+)</dcterms:created>",
        "modified": r"<dcterms:modified[^>]*>([^<]+)</dcterms:modified>",
    }
    
    for field, pattern in patterns.items():
        match = re.search(pattern, content)
        if match:
            metadata[field] = match.group(1)
    
    return metadata


def extract_metadata_markdown(content: str) -> Dict[str, Any]:
    """
    提取 Markdown 元数据（Front Matter）
    
    Args:
        content: Markdown 文件内容
    
    Returns:
        元数据字典
    """
    metadata = {}
    
    # 提取 YAML Front Matter
    front_matter_match = re.match(r'^---\s*\n(.*?)\n---\s*\n', content, re.DOTALL)
    if front_matter_match:
        front_matter = front_matter_match.group(1)
        for line in front_matter.split('\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                metadata[key.strip()] = value.strip()
    
    # 提取 HTML 注释
    comments = re.findall(r'<!--\s*(.*?)\s*-->', content, re.DOTALL)
    if comments:
        metadata["comments"] = comments
    
    return metadata


def extract_metadata_html(content: str) -> Dict[str, Any]:
    """
    提取 HTML 元数据
    
    Args:
        content: HTML 文件内容
    
    Returns:
        元数据字典
    """
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
    
    return metadata


def detect_file_type(file_path: str) -> str:
    """
    检测文件类型
    
    Args:
        file_path: 文件路径
    
    Returns:
        文件类型 (pdf, docx, md, html, ttl, rdf, json-ld)
    """
    ext = Path(file_path).suffix.lower()
    
    type_map = {
        ".pdf": "pdf",
        ".docx": "docx",
        ".doc": "docx",
        ".md": "md",
        ".markdown": "md",
        ".html": "html",
        ".htm": "html",
        ".ttl": "ttl",
        ".turtle": "ttl",
        ".rdf": "rdf",
        ".xml": "rdf",
        ".json": "json-ld",
        ".jsonld": "json-ld",
    }
    
    return type_map.get(ext, "unknown")
