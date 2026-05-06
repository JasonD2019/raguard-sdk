"""
License 缓存模块

提供本地缓存功能，支持 7 天宽容期。
"""

import hashlib
import hmac
import json
import time
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, Optional

from ..utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class LicenseCacheData:
    """License 缓存数据"""
    license_key: str
    plan: str  # trial|professional|enterprise|project
    quota: Dict[str, Any]
    features: list
    expire_at: str  # ISO format
    last_success_verify: str  # ISO format
    machine_id: str
    signature: str  # HMAC 签名


class LicenseCache:
    """License 缓存管理器"""
    
    # 宽容期天数
    GRACE_PERIOD_DAYS = 7
    
    # 缓存文件路径
    DEFAULT_CACHE_FILE = Path.home() / ".raguard" / "license_cache.json"
    
    # HMAC 密钥（生产环境应从安全位置获取）
    _SECRET_KEY = b"raguard_secret_key_change_in_production"
    
    def __init__(self, cache_file: Optional[Path] = None, cache_path: Optional[str] = None):
        """
        初始化 License 缓存
        
        Args:
            cache_file: 缓存文件路径
            cache_path: 缓存文件路径（字符串形式，兼容测试）
        """
        self.cache_file = cache_file or (Path(cache_path) if cache_path else self.DEFAULT_CACHE_FILE)
        self._ensure_cache_dir()
        self._cache: Dict[str, LicenseCacheData] = self._load_cache()
        # 用于测试的内部数据访问
        self._data: Dict[str, Any] = {}
        
        logger.info(f"LicenseCache 初始化完成，缓存文件：{self.cache_file}")
    
    def _ensure_cache_dir(self):
        """确保缓存目录存在"""
        self.cache_file.parent.mkdir(parents=True, exist_ok=True)
    
    def _load_cache(self) -> Dict[str, LicenseCacheData]:
        """加载缓存文件"""
        if not self.cache_file.exists():
            return {}
        
        try:
            with open(self.cache_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                return {k: LicenseCacheData(**v) for k, v in data.items()}
        except Exception as e:
            logger.error(f"加载缓存失败：{e}")
            return {}
    
    def _save_cache(self):
        """保存缓存文件"""
        try:
            data = {k: asdict(v) for k, v in self._cache.items()}
            with open(self.cache_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error(f"保存缓存失败：{e}")
    
    def _generate_signature(self, data: Dict[str, Any]) -> str:
        """生成 HMAC 签名"""
        # 对关键字段签名
        message = f"{data.get('license_key', '')}:{data.get('machine_id', '')}:{data.get('expire_at', '')}"
        signature = hmac.new(
            self._SECRET_KEY,
            message.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        return signature
    
    def _verify_signature(self, cache_data: LicenseCacheData) -> bool:
        """验证缓存数据签名"""
        data = {
            'license_key': cache_data.license_key,
            'machine_id': cache_data.machine_id,
            'expire_at': cache_data.expire_at
        }
        expected_signature = self._generate_signature(data)
        return hmac.compare_digest(cache_data.signature, expected_signature)
    
    def get(self, license_key: str) -> Optional[LicenseCacheData]:
        """
        获取缓存的 License 数据
        
        Args:
            license_key: License Key
        
        Returns:
            LicenseCacheData 或 None
        """
        return self._cache.get(license_key)
    
    def set(self, license_key: str, data: Dict[str, Any]):
        """
        设置缓存数据（用于测试）
        
        Args:
            license_key: License Key
            data: 缓存数据
        """
        # 用于测试的内部数据存储
        self._data[license_key] = data
        
        # 如果数据包含必要字段，也更新正式缓存
        if all(k in data for k in ['plan', 'quota', 'features', 'expire_at', 'last_success_verify', 'machine_id']):
            cache_data = LicenseCacheData(
                license_key=license_key,
                plan=data.get('plan', 'trial'),
                quota=data.get('quota', {}),
                features=data.get('features', []),
                expire_at=data.get('expire_at', ''),
                last_success_verify=data.get('last_success_verify', time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())),
                machine_id=data.get('machine_id', 'machine_test'),
                signature=""
            )
            self.update(cache_data)
        else:
            # 即使数据不完整，也创建一个基本的缓存条目并保存文件
            cache_data = LicenseCacheData(
                license_key=license_key,
                plan=data.get('plan', 'trial'),
                quota=data.get('quota', {}),
                features=data.get('features', []),
                expire_at=data.get('expire_at', time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())),
                last_success_verify=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                machine_id=data.get('machine_id', 'machine_test'),
                signature=""
            )
            self.update(cache_data)
    
    def update(self, cache_data: LicenseCacheData):
        """
        更新缓存
        
        Args:
            cache_data: License 缓存数据
        """
        # 生成签名
        data = {
            'license_key': cache_data.license_key,
            'machine_id': cache_data.machine_id,
            'expire_at': cache_data.expire_at,
            'plan': cache_data.plan,
            'quota': cache_data.quota,
            'features': cache_data.features,
            'last_success_verify': cache_data.last_success_verify
        }
        cache_data.signature = self._generate_signature(data)
        
        self._cache[cache_data.license_key] = cache_data
        self._save_cache()
        
        logger.info(f"License 缓存已更新：{cache_data.license_key}")
    
    def remove(self, license_key: str):
        """移除缓存"""
        if license_key in self._cache:
            del self._cache[license_key]
            self._save_cache()
            logger.info(f"License 缓存已移除：{license_key}")
    
    def is_grace_period_valid(self, cache_data: LicenseCacheData) -> bool:
        """
        检查是否在宽容期内
        
        Args:
            cache_data: License 缓存数据
        
        Returns:
            True 如果在宽容期内
        """
        try:
            last_verify_str = cache_data.last_success_verify
            # 支持多种格式
            if isinstance(cache_data, dict):
                last_verify_str = cache_data.get('last_success_verify', '')
            
            # 处理 ISO 格式
            last_verify_str = last_verify_str.replace('Z', '+00:00')
            if '+' not in last_verify_str and last_verify_str.count('-') == 2:
                # 无时区信息
                last_verify = datetime.fromisoformat(last_verify_str)
                now = datetime.now()
            else:
                last_verify = datetime.fromisoformat(last_verify_str)
                now = datetime.now(last_verify.tzinfo) if last_verify.tzinfo else datetime.now()
            
            grace_end = last_verify + timedelta(days=self.GRACE_PERIOD_DAYS)
            
            is_valid = now <= grace_end
            
            if not is_valid:
                logger.warning(
                    f"宽容期已结束：最后验证={last_verify}, 宽容期结束={grace_end}"
                )
            
            return is_valid
        except Exception as e:
            logger.error(f"检查宽容期失败：{e}")
            return False
    
    def get_grace_period_remaining(self, cache_data: LicenseCacheData) -> int:
        """
        获取宽容期剩余天数
        
        Args:
            cache_data: License 缓存数据
        
        Returns:
            剩余天数（负数表示已过期）
        """
        try:
            last_verify_str = cache_data.last_success_verify
            # 支持多种格式
            if isinstance(cache_data, dict):
                last_verify_str = cache_data.get('last_success_verify', '')
            
            # 处理 ISO 格式
            last_verify_str = last_verify_str.replace('Z', '+00:00')
            if '+' not in last_verify_str and last_verify_str.count('-') == 2:
                last_verify = datetime.fromisoformat(last_verify_str)
                now = datetime.now()
            else:
                last_verify = datetime.fromisoformat(last_verify_str)
                now = datetime.now(last_verify.tzinfo) if last_verify.tzinfo else datetime.now()
            
            grace_end = last_verify + timedelta(days=self.GRACE_PERIOD_DAYS)
            remaining = (grace_end - now).days
            
            return remaining
        except Exception as e:
            logger.error(f"计算宽容期剩余天数失败：{e}")
            return -1
    
    def clear_expired(self):
        """清理过期的缓存"""
        expired_keys = []
        
        for key, cache_data in self._cache.items():
            try:
                expire_at = datetime.fromisoformat(cache_data.expire_at.replace('Z', '+00:00'))
                now = datetime.now(expire_at.tzinfo) if expire_at.tzinfo else datetime.now()
                
                if now > expire_at:
                    # 检查宽容期
                    if not self.is_grace_period_valid(cache_data):
                        expired_keys.append(key)
            except Exception as e:
                logger.error(f"检查缓存过期失败 {key}: {e}")
                expired_keys.append(key)
        
        for key in expired_keys:
            self.remove(key)
        
        if expired_keys:
            logger.info(f"清理了 {len(expired_keys)} 个过期缓存")
    
    def clear_all(self):
        """清空所有缓存"""
        self._cache.clear()
        self._save_cache()
        logger.info("所有 License 缓存已清空")


# 全局缓存实例
_cache_instance: Optional[LicenseCache] = None


def get_cache() -> LicenseCache:
    """获取全局缓存实例"""
    global _cache_instance
    if _cache_instance is None:
        _cache_instance = LicenseCache()
    return _cache_instance
