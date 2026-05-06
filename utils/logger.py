"""
统一日志模块

提供标准化的日志输出，支持不同级别和格式。
"""

import logging
import sys
from typing import Optional


def get_logger(
    name: str,
    level: int = logging.INFO,
    log_file: Optional[str] = None
) -> logging.Logger:
    """
    获取配置好的 logger 实例
    
    Args:
        name: logger 名称（通常使用 __name__）
        level: 日志级别
        log_file: 日志文件路径（可选）
    
    Returns:
        配置好的 Logger 实例
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # 避免重复添加 handler
    if logger.handlers:
        return logger
    
    # 创建 formatter
    formatter = logging.Formatter(
        fmt='%(asctime)s | %(levelname)-8s | %(name)s | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # 控制台 handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # 文件 handler（可选）
    if log_file:
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    return logger


# 全局默认 logger
default_logger = get_logger("raguard")


def debug(msg: str, *args, **kwargs):
    """输出 DEBUG 级别日志"""
    default_logger.debug(msg, *args, **kwargs)


def info(msg: str, *args, **kwargs):
    """输出 INFO 级别日志"""
    default_logger.info(msg, *args, **kwargs)


def warning(msg: str, *args, **kwargs):
    """输出 WARNING 级别日志"""
    default_logger.warning(msg, *args, **kwargs)


def error(msg: str, *args, **kwargs):
    """输出 ERROR 级别日志"""
    default_logger.error(msg, *args, **kwargs)


def critical(msg: str, *args, **kwargs):
    """输出 CRITICAL 级别日志"""
    default_logger.critical(msg, *args, **kwargs)
