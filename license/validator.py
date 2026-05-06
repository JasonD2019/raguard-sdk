"""
License 验证模块

提供在线验证、本地缓存、宽容期管理等功能。
"""

import hashlib
import platform
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

import requests

from ..utils.logger import get_logger
from ..utils.metrics import global_collector
from .cache import LicenseCache, LicenseCacheData, get_cache

logger = get_logger(__name__)


class LicenseStatus(Enum):
    """License 状态"""
    VALID = "valid"
    GRACE_PERIOD = "grace_period"
    DEGRADED = "degraded"
    INVALID = "invalid"
    INVALID_FORMAT = "invalid_format"
    EXPIRED = "expired"
    REVOKED = "revoked"
    MACHINE_MISMATCH = "machine_mismatch"
    GRACE_PERIOD_EXPIRED = "grace_period_expired"


@dataclass
class LicenseInfo:
    """License 信息"""
    valid: bool
    status: str
    plan: str = ""
    quota: Dict[str, Any] = None
    features: List[str] = None
    expire_at: str = ""
    grace_period_remaining: int = 0
    error: str = ""
    
    def __post_init__(self):
        if self.quota is None:
            self.quota = {}
        if self.features is None:
            self.features = []
    
    @property
    def is_valid(self) -> bool:
        return self.valid


class LicenseValidator:
    """License 验证器"""
    
    API_BASE_URL = "https://api.raguard.com/v1"
    API_TIMEOUT = 10
    LICENSE_KEY_PATTERN = re.compile(r'^(RAG-[A-Z]+-\d{4}-[A-Z0-9]{5,}$|TEST-KEY-[A-Z]+)')
    
    def __init__(
        self,
        license_key: Optional[str] = None,
        cache: Optional[LicenseCache] = None,
        api_url: Optional[str] = None
    ):
        self.license_key = license_key
        self.cache = cache or get_cache()
        self.api_base_url = api_url or self.API_BASE_URL
        self.machine_id = self._get_machine_id()
        self._license_info: Optional[LicenseInfo] = None
        logger.info(f"LicenseValidator 初始化完成，machine_id={self.machine_id}")
    
    def _get_machine_id(self) -> str:
        try:
            node = platform.node()
            processor = platform.processor()
            machine = platform.machine()
            raw_id = f"{node}:{processor}:{machine}"
            machine_id = hashlib.sha256(raw_id.encode('utf-8')).hexdigest()[:16]
            return f"machine_{machine_id}"
        except Exception as e:
            logger.error(f"获取机器 ID 失败：{e}")
            return f"machine_unknown_{int(time.time())}"
    
    def verify(self, license_key: Optional[str] = None) -> LicenseInfo:
        key = license_key or self.license_key
        
        if not key:
            return LicenseInfo(valid=False, status=LicenseStatus.INVALID.value, error="未提供 License Key")
        
        if not self._validate_license_format(key):
            return LicenseInfo(valid=False, status=LicenseStatus.INVALID_FORMAT.value, error="License Key 格式无效")
        
        start_time = time.perf_counter()
        
        try:
            info = self._online_verify(key)
            if info.valid:
                duration_ms = int((time.perf_counter() - start_time) * 1000)
                logger.info(f"License 在线验证成功：{key[:20]}..., plan={info.plan}, {duration_ms}ms")
                return info
        except Exception as e:
            logger.warning(f"在线验证失败，使用本地缓存：{e}")
        
        cached = self.cache.get(key)
        if cached:
            if not self.cache._verify_signature(cached):
                logger.error("License 缓存签名验证失败，可能被篡改")
                return LicenseInfo(valid=False, status=LicenseStatus.INVALID.value, error="License 缓存验证失败")
            
            if self.cache.is_grace_period_valid(cached):
                remaining = self.cache.get_grace_period_remaining(cached)
                return LicenseInfo(
                    valid=True,
                    status=LicenseStatus.GRACE_PERIOD.value,
                    plan=cached.plan,
                    quota=cached.quota,
                    features=cached.features,
                    expire_at=cached.expire_at,
                    grace_period_remaining=remaining
                )
            else:
                return LicenseInfo(
                    valid=False,
                    status=LicenseStatus.GRACE_PERIOD_EXPIRED.value,
                    plan=cached.plan,
                    error="宽容期已结束，请恢复网络连接重新验证"
                )
        
        return LicenseInfo(valid=False, status=LicenseStatus.INVALID.value, error="License 验证失败")
    
    def _validate_license_format(self, license_key: str) -> bool:
        if not license_key:
            return False
        if not self.LICENSE_KEY_PATTERN.match(license_key):
            return False
        if any(char in license_key for char in ['<', '>', '"', "'", '&', '\\', '/']):
            return False
        return True
    
    def _online_verify(self, license_key: str) -> LicenseInfo:
        url = f"{self.api_base_url}/license/verify"
        payload = {
            "license_key": license_key,
            "product_version": "1.0.0",
            "machine_id": self.machine_id
        }
        
        try:
            response = requests.post(url, json=payload, timeout=self.API_TIMEOUT)
            response.raise_for_status()
            data = response.json()
            
            if data.get("code") != 0:
                error_code = data.get("code", -1)
                error_msg = data.get("message", "未知错误")
                
                if error_code == 1002:
                    return LicenseInfo(valid=False, status=LicenseStatus.EXPIRED.value, error=f"License 已过期：{error_msg}")
                elif error_code == 1003:
                    return LicenseInfo(valid=False, status=LicenseStatus.REVOKED.value, error=f"License 已被吊销：{error_msg}")
                elif error_code == 1004:
                    return LicenseInfo(valid=False, status=LicenseStatus.MACHINE_MISMATCH.value, error=f"机器 ID 不匹配：{error_msg}")
                else:
                    return LicenseInfo(valid=False, status=LicenseStatus.INVALID.value, error=f"验证失败：{error_msg}")
            
            result_data = data.get("data", {})
            cache_data = LicenseCacheData(
                license_key=license_key,
                plan=result_data.get("plan", "trial"),
                quota=result_data.get("quota", {}),
                features=result_data.get("features", []),
                expire_at=result_data.get("expire_at", ""),
                last_success_verify=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                machine_id=self.machine_id,
                signature=""
            )
            self.cache.update(cache_data)
            
            return LicenseInfo(
                valid=True,
                status=LicenseStatus.VALID.value,
                plan=result_data.get("plan", "trial"),
                quota=result_data.get("quota", {}),
                features=result_data.get("features", []),
                expire_at=result_data.get("expire_at", "")
            )
        except requests.exceptions.RequestException as e:
            raise Exception(f"网络请求失败：{e}")
        except Exception as e:
            raise Exception(f"验证失败：{e}")
    
    def get_status(self) -> str:
        if self._license_info:
            return self._license_info.status
        return "invalid"
    
    def get_plan(self) -> str:
        if self._license_info:
            return self._license_info.plan
        return "unknown"
    
    def has_feature(self, feature: str) -> bool:
        if self._license_info:
            return feature in self._license_info.features
        return False
    
    def check_quota(self, feature: str, count: int = 1) -> bool:
        if not self._license_info:
            return False
        quota = self._license_info.quota
        if not quota:
            return True
        monthly_limit = quota.get(f"{feature}_limit") or quota.get("monthly_limit")
        used = quota.get(f"{feature}_used", 0)
        if monthly_limit:
            return (used + count) <= monthly_limit
        return True
    
    def refresh(self) -> LicenseInfo:
        if self.license_key:
            self._license_info = self.verify(self.license_key)
        return self._license_info or LicenseInfo(valid=False, status=LicenseStatus.INVALID.value)


_validator_instance: Optional[LicenseValidator] = None


def init_license(license_key: str) -> LicenseInfo:
    global _validator_instance
    _validator_instance = LicenseValidator(license_key)
    return _validator_instance.verify()


def get_validator() -> Optional[LicenseValidator]:
    return _validator_instance


def verify_license(license_key: Optional[str] = None) -> LicenseInfo:
    global _validator_instance
    if _validator_instance is None:
        _validator_instance = LicenseValidator(license_key)
    return _validator_instance.verify(license_key)


def api_verify(license_key: str) -> Dict[str, Any]:
    validator = LicenseValidator(license_key)
    info = validator.verify(license_key)
    return {"valid": info.valid, "status": info.status, "plan": info.plan, "error": info.error}


def get_machine_id() -> str:
    validator = LicenseValidator()
    return validator.machine_id
