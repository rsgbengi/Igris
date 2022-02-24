from typing import Tuple
from logging import Logger
from loguru import logger
import sys
from log_symbols import LogSymbols
from cmd2 import CommandSet


class LoggersConfiguration(CommandSet):
    def __init__(self) -> None:
        super().__init__()

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
