from loguru import logger
import sys

fmt = "{level.icon} {message}"
logger.add(
    sys.stdout,
    colorize=True,
    level="INFO",
    format=fmt,
    filter=lambda record: record["extra"].get("name") == "info",
)
logger.add(
    sys.stderr,
    colorize=True,
    level="WARNING",
    format=fmt,
    filter=lambda record: record["extra"].get("name") == "error",
)
logger.info()
