import logging
import time
from contextlib import contextmanager
from typing import Iterator

_DEFAULT_NAME = "invsol_ast"


def get_logger(name: str = _DEFAULT_NAME) -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        fmt = "[%(asctime)s] %(levelname)s %(name)s: %(message)s"
        handler.setFormatter(logging.Formatter(fmt))
        logger.addHandler(handler)
        logger.propagate = False
    return logger


# Convenience shorthands
def info(msg: str) -> None:
    get_logger().info(msg)


def debug(msg: str) -> None:
    get_logger().debug(msg)


def warning(msg: str) -> None:
    get_logger().warning(msg)


def error(msg: str) -> None:
    get_logger().error(msg)


@contextmanager
def timed(section: str) -> Iterator[None]:
    """Simple timing context for phases like parse/normalize/extract/build."""
    logger = get_logger()
    start = time.time()
    logger.info(f"▶ {section} …")
    try:
        yield
    finally:
        elapsed = (time.time() - start) * 1000.0
        logger.info(f"✔ {section} done in {elapsed:.1f} ms")
