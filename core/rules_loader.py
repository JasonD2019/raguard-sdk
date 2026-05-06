"""
统一规则加载器

支持从 ragshield-rules 或 raguard 内置规则加载规则。
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ..utils.logger import get_logger

logger = get_logger(__name__)


class RulesLoader:
    """
    统一规则加载器

    支持加载:
    - ragshield-rules 格式 (子模块或直接路径)
    - raguard 内置规则格式
    """

    def __init__(self, rules_dir: Optional[str] = None):
        """
        初始化规则加载器

        Args:
            rules_dir: 规则目录路径，支持:
                      - None: 自动检测 (ragshield-rules 或 raguard/rules)
                      - ragshield-rules 路径
                      - raguard/rules 路径
        """
        if rules_dir:
            self.rules_dir = Path(rules_dir)
        else:
            self.rules_dir = self._detect_rules_dir()

        logger.info(f"RulesLoader 初始化，规则目录: {self.rules_dir}")

    def _detect_rules_dir(self) -> Path:
        """自动检测规则目录"""
        # 优先使用 ragshield-rules
        possible_paths = [
            # 项目根目录下的 ragshield-rules
            Path(__file__).parent.parent.parent.parent / "ragshield-rules",
            # workspace-ragshield 下的 ragshield-rules
            Path(__file__).parent.parent.parent / "ragshield-rules",
            # raguard 内置规则
            Path(__file__).parent.parent / "rules",
        ]

        for path in possible_paths:
            if path.exists() and (path / "rules").exists():
                logger.info(f"检测到规则目录: {path}")
                return path

        # 默认使用 raguard 内置规则
        default = Path(__file__).parent.parent / "rules"
        logger.warning(f"未检测到规则目录，使用默认: {default}")
        return default

    def load_category(self, category: str) -> List[Dict]:
        """
        加载指定类别的所有规则

        Args:
            category: injection, jailbreak, sensitive, privacy

        Returns:
            规则列表
        """
        rules = []
        category_dir = self.rules_dir / "rules" / category

        if not category_dir.exists():
            # 尝试加载合并文件 (raguard 格式)
            merged_file = self.rules_dir / f"{category}_rules.json"
            if merged_file.exists():
                with open(merged_file, encoding='utf-8') as f:
                    data = json.load(f)
                    rules.extend(data.get("rules", []))
            else:
                logger.warning(f"规则类别目录不存在: {category_dir}")
            return rules

        # 加载目录下所有 JSON 文件
        for file in category_dir.glob("*.json"):
            try:
                with open(file, encoding='utf-8') as f:
                    data = json.load(f)
                    for rule in data.get("rules", []):
                        # 添加类别标记
                        rule["category"] = category
                        rules.append(rule)
            except Exception as e:
                logger.error(f"加载规则文件失败 {file}: {e}")

        logger.info(f"加载 {category} 规则: {len(rules)} 条")
        return rules

    def load_all_patterns(self, category: str) -> List[str]:
        """加载指定类别的所有 pattern"""
        patterns = []
        rules = self.load_category(category)

        for rule in rules:
            patterns.extend(rule.get("patterns", []))

        return patterns

    def load_sensitive_words(self) -> List[str]:
        """加载敏感词列表"""
        words = []

        # 尝试加载合并文件 (raguard 格式)
        merged_file = self.rules_dir / "sensitive_words.json"
        if merged_file.exists():
            with open(merged_file, encoding='utf-8') as f:
                data = json.load(f)
                for rule in data.get("rules", []):
                    words.extend(rule.get("patterns", []))
            return words

        # 加载分类文件 (ragshield-rules 格式)
        category_dir = self.rules_dir / "rules" / "sensitive"
        if category_dir.exists():
            for file in category_dir.glob("*.json"):
                try:
                    with open(file, encoding='utf-8') as f:
                        data = json.load(f)
                        # ragshield-rules 格式: words 数组
                        if "words" in data:
                            words.extend(data["words"])
                        # 兼容 rules 格式
                        elif "rules" in data:
                            for rule in data.get("rules", []):
                                words.extend(rule.get("patterns", []))
                except Exception as e:
                    logger.error(f"加载敏感词文件失败 {file}: {e}")

        logger.info(f"加载敏感词: {len(words)} 个")
        return words

    def load_privacy_rules(self) -> List[Dict]:
        """
        加载隐私正则规则

        隐私规则使用 `pattern` 字段存储单个正则表达式
        """
        rules = []

        # 加载分类文件
        category_dir = self.rules_dir / "rules" / "privacy"
        if category_dir.exists():
            for file in category_dir.glob("*.json"):
                try:
                    with open(file, encoding='utf-8') as f:
                        data = json.load(f)
                        for rule in data.get("rules", []):
                            # 将 pattern 字段转换为 patterns 数组 (统一格式)
                            if "pattern" in rule and "patterns" not in rule:
                                rule["patterns"] = [rule["pattern"]]
                            rule["category"] = "privacy"
                            rules.append(rule)
                except Exception as e:
                    logger.error(f"加载隐私规则文件失败 {file}: {e}")

        # 尝试加载合并文件
        merged_file = self.rules_dir / "privacy_patterns.json"
        if merged_file.exists():
            with open(merged_file, encoding='utf-8') as f:
                data = json.load(f)
                for rule in data.get("rules", []):
                    if "pattern" in rule and "patterns" not in rule:
                        rule["patterns"] = [rule["pattern"]]
                    rule["category"] = "privacy"
                    rules.append(rule)

        logger.info(f"加载隐私规则: {len(rules)} 条")
        return rules

    def compile_patterns(self, rules: List[Dict]) -> List[Tuple[Dict, Optional[re.Pattern]]]:
        """
        编译规则为正则表达式

        Returns:
            [(rule, compiled_pattern), ...]
        """
        compiled = []

        for rule in rules:
            patterns = rule.get("patterns", [])
            if not patterns:
                continue

            rule_type = rule.get("rule_type", "keyword")

            try:
                if rule_type == "pattern":
                    # pattern 类型直接拼接为正则
                    pattern = re.compile('|'.join(patterns), re.IGNORECASE)
                else:
                    # keyword 类型需要转义
                    pattern = re.compile(
                        '|'.join(re.escape(p) for p in patterns),
                        re.IGNORECASE
                    )
                compiled.append((rule, pattern))
            except re.error as e:
                logger.warning(f"规则 {rule['rule_id']} 正则编译失败: {e}")
                compiled.append((rule, None))

        return compiled

    def get_stats(self) -> Dict:
        """获取规则统计"""
        stats = {
            "rules_dir": str(self.rules_dir),
            "categories": {}
        }

        for category in ["injection", "jailbreak"]:
            rules = self.load_category(category)
            patterns = sum(len(r.get("patterns", [])) for r in rules)
            stats["categories"][category] = {
                "rules": len(rules),
                "patterns": patterns
            }

        # 敏感词统计
        sensitive_words = self.load_sensitive_words()
        stats["categories"]["sensitive"] = {
            "rules": 1,
            "words": len(sensitive_words)
        }

        # 隐私正则统计
        privacy_rules = self.load_privacy_rules()
        stats["categories"]["privacy"] = {
            "rules": len(privacy_rules),
            "patterns": sum(len(r.get("patterns", [])) for r in privacy_rules)
        }

        return stats


# 便捷加载函数
_loader_instance: Optional[RulesLoader] = None


def get_rules_loader(rules_dir: Optional[str] = None) -> RulesLoader:
    """获取规则加载器单例"""
    global _loader_instance
    if _loader_instance is None or rules_dir:
        _loader_instance = RulesLoader(rules_dir)
    return _loader_instance


def load_injection_rules() -> List[Dict]:
    """加载注入规则"""
    return get_rules_loader().load_category("injection")


def load_jailbreak_rules() -> List[Dict]:
    """加载越狱规则"""
    return get_rules_loader().load_category("jailbreak")


def load_sensitive_words() -> List[str]:
    """加载敏感词"""
    return get_rules_loader().load_sensitive_words()


def load_privacy_rules() -> List[Dict]:
    """加载隐私正则规则"""
    return get_rules_loader().load_privacy_rules()