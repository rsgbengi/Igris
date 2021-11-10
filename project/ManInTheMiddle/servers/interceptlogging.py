from loguru import logger
import logging
import cmd2
import sys
import re

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


class InterceptHandlerOnlyFilesMss(logging.Handler):
    def __init__(self, alerts_dictionary: dict, ntlmv2_collected: list):
        super().__init__()
        self.__alerts_dictionary = alerts_dictionary
        self.__ntlmv2_collected = ntlmv2_collected

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
        if (
            "::" in record.getMessage()
            and record.getMessage() not in self.__ntlmv2_collected
        ):
            self.__users_collected.append(record.getMessage())
            self.__alerts_dictionary["new_ntlmv2"] = 1

        logger.opt(depth=depth, exception=record.exc_info).log(
            level, record.getMessage()
        )


class InterceptHandlerOnlyFilesNtlmRelay(logging.Handler):
    def __init__(self, alerts_dictionary):
        super().__init__()
        self.__alerts_dictionary = alerts_dictionary

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
            self.__alerts_dictionary["sam_dump"] = 1

        if "Enjoy" in record.getMessage():
            self.__alerts_dictionary["new_connection"] = 1

        logger.opt(depth=depth, exception=record.exc_info).log(
            level, record.getMessage()
        )
