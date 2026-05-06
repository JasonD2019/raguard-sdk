"""
性能指标收集模块

用于收集和统计 SDK 的性能指标，包括响应时间、调用次数等。
"""

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from contextlib import contextmanager
import threading


@dataclass
class MetricRecord:
    """单次指标记录"""
    name: str
    duration_ms: float
    timestamp: float = field(default_factory=time.time)
    success: bool = True
    error: Optional[str] = None


class MetricsCollector:
    """
    指标收集器
    
    线程安全，支持并发调用统计。
    """
    
    def __init__(self):
        self._records: Dict[str, List[MetricRecord]] = {}
        self._lock = threading.Lock()
    
    def record(self, name: str, duration_ms: float, success: bool = True, error: Optional[str] = None):
        """
        记录一次指标
        
        Args:
            name: 指标名称（如 'doc_scanner', 'prompt_checker'）
            duration_ms: 耗时（毫秒）
            success: 是否成功
            error: 错误信息（如果有）
        """
        record = MetricRecord(
            name=name,
            duration_ms=duration_ms,
            success=success,
            error=error
        )
        
        with self._lock:
            if name not in self._records:
                self._records[name] = []
            self._records[name].append(record)
    
    @contextmanager
    def measure(self, name: str):
        """
        上下文管理器，自动记录耗时
        
        Usage:
            with collector.measure('doc_scanner'):
                # 执行代码
                pass
        """
        start_time = time.perf_counter()
        success = True
        error = None
        
        try:
            yield
        except Exception as e:
            success = False
            error = str(e)
            raise
        finally:
            duration_ms = (time.perf_counter() - start_time) * 1000
            self.record(name, duration_ms, success, error)
    
    def get_stats(self, name: str) -> Dict:
        """
        获取指定指标的统计信息
        
        Args:
            name: 指标名称
        
        Returns:
            统计字典，包含 count, avg, min, max, p50, p90, p99
        """
        with self._lock:
            records = self._records.get(name, [])
        
        if not records:
            return {
                'count': 0,
                'avg': 0,
                'min': 0,
                'max': 0,
                'p50': 0,
                'p90': 0,
                'p99': 0,
            }
        
        durations = sorted([r.duration_ms for r in records])
        count = len(durations)
        
        def percentile(p: int) -> float:
            idx = int(count * p / 100)
            return durations[min(idx, count - 1)]
        
        return {
            'count': count,
            'avg': sum(durations) / count,
            'min': durations[0],
            'max': durations[-1],
            'p50': percentile(50),
            'p90': percentile(90),
            'p99': percentile(99),
            'success_rate': sum(1 for r in records if r.success) / count,
        }
    
    def get_all_stats(self) -> Dict[str, Dict]:
        """获取所有指标的统计信息"""
        with self._lock:
            names = list(self._records.keys())
        
        return {name: self.get_stats(name) for name in names}
    
    def reset(self, name: Optional[str] = None):
        """
        重置指标数据
        
        Args:
            name: 指定指标名称（None 表示重置所有）
        """
        with self._lock:
            if name:
                self._records.pop(name, None)
            else:
                self._records.clear()


# 全局指标收集器
global_collector = MetricsCollector()


def record_metric(name: str, duration_ms: float, success: bool = True, error: Optional[str] = None):
    """记录指标（使用全局收集器）"""
    global_collector.record(name, duration_ms, success, error)


def get_metric_stats(name: str) -> Dict:
    """获取指标统计（使用全局收集器）"""
    return global_collector.get_stats(name)
