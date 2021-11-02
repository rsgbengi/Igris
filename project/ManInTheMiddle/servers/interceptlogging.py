from loguru import logger
import logging
import cmd2
import sys

# https://stackoverflow.com/questions/65329555/standard-library-logging-plus-loguru
class InterceptHandlerStdout(logging.Handler):
    def emit(self, record):
        # Get corresponding Loguru level if it exists
        try:
            level = logger.level(record.levelname).name
        except ValueError:
            level = record.levelno
        # Find caller from where originated the logged message
        frame, depth = logging.currentframe(), 2
        while frame.f_code.co_filename == logging.__file__:
            frame = frame.f_back
            depth += 1
        if level == "INFO":
            logger.bind(name="info").opt(depth=depth, exception=record.exc_info).log(
                level, record.getMessage()
            )
        elif level != "DEBUG":
            logger.bind(name="error").opt(depth=depth, exception=record.exc_info).log(
                level, record.getMessage()
            )


class InterceptHandlerOnlyFiles(logging.Handler):
    def emit(self, record):
        # Get corresponding Loguru level if it exists
        try:
            level = logger.level(record.levelname).name
        except ValueError:
            level = record.levelno
        # Find caller from where originated the logged message
        frame, depth = logging.currentframe(), 2
        while frame.f_code.co_filename == logging.__file__:
            frame = frame.f_back
            depth += 1
        if "Done dumping SAM hashes for host:" in record.getMessage():
            logger.bind(name="info").opt(depth=depth, exception=record.exc_info).log(
                level, record.getMessage()
            )
        if "Enjoy" in record.getMessage():
            logger.bind(name="info").opt(depth=depth, exception=record.exc_info).log(
                level, record.getMessage()
            )

        logger.opt(depth=depth, exception=record.exc_info).log(
            level, record.getMessage()
        )
