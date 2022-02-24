from typing import Tuple
from cmd2 import CommandSet
from loguru import logger
from logging import Logger
from log_symbols import LogSymbols
import sys


class LoggersConfiguration(CommandSet):
    def __init__(self) -> None:
        super().__init__()

    def set_up_file_loggers(self) -> None:
        logger.add("logs/all.log", level="DEBUG", rotation="1 week", enqueue=True)
        logger.add(
            "logs/info_and_above.log", level="INFO", rotation="1 week", enqueue=True
        )

    def set_up_output_loggers(self) -> Tuple[Logger, Logger]:
        """[ Function to prepare the logger ]"""
        # export LOGURU_AUTOINIT=False

        logger.level("DEBUG", icon=LogSymbols.INFO.value)
        logger.level("SUCCESS", icon=LogSymbols.SUCCESS.value)
        logger.level("INFO", icon=LogSymbols.INFO.value)
        logger.level("WARNING", icon=LogSymbols.WARNING.value)
        logger.level("ERROR", icon=LogSymbols.ERROR.value)
        fmt = "{level.icon} {message}"
        logger.add(
            sink=self._cmd.stdout,
            level="INFO",
            format=fmt,
            filter=lambda record: record["extra"].get("name") == "info",
        )

        logger.add(
            sink=sys.stderr,
            level="WARNING",
            format=fmt,
            filter=lambda record: record["extra"].get("name") == "error",
        )

        info_logger = logger.bind(name="info")
        error_logger = logger.bind(name="error")
        return info_logger, error_logger
