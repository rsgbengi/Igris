from loguru import logger
from typing import Tuple
import logging
from logging import LogRecord
import cmd2
import sys
import os
import re


class InterceptHandlerMss(logging.Handler):
    def __init__(
        self, path_file: str, ntlmv2_collected: dict, alerts_dictionary: dict = None
    ) -> None:
        super().__init__()
        self.__path_file = path_file
        self.__ntlmv2_collected = ntlmv2_collected
        self.__alerts_dictionary = alerts_dictionary

    def __open_the_file(self, message: str) -> None:
        file_created = f"{self.__path_file}/ntlmv2_hashes.txt"
        if os.path.exists(file_created):
            with open(file_created, "a") as output_file:
                output_file.write(message + "\n")
        else:
            with open(file_created, "w") as output_file:
                output_file.write(message + "\n")

    def __save_hashes(self, message: str) -> None:
        if "::" in message:
            user = message.split("::")[0]
            if user not in self.__ntlmv2_collected.keys():
                self.__ntlmv2_collected[user] = message
                if self.__alerts_dictionary != None:
                    self.__alerts_dictionary["new_ntlmv2"] = 1
                self.__open_the_file(message)

    def emit(self, record: LogRecord) -> Tuple[str, int]:
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
        self.__save_hashes(record.getMessage())
        return (
            level,
            depth,
        )


# https://stackoverflow.com/questions/65329555/standard-library-logging-plus-loguru
class InterceptHandlerStdoutMss(InterceptHandlerMss):
    def __init__(self, path_file: str, ntlmv2_collected: dict) -> None:
        super().__init__(path_file, ntlmv2_collected)

    def emit(self, record) -> None:

        level, depth = super().emit(record)
        if level == "INFO":
            logger.bind(name="info").opt(depth=depth, exception=record.exc_info).log(
                level, record.getMessage()
            )
        elif level != "DEBUG":
            logger.bind(name="error").opt(depth=depth, exception=record.exc_info).log(
                level, record.getMessage()
            )


class InterceptHandlerOnlyFilesMss(InterceptHandlerMss):
    def __init__(self, alerts_dictionary: dict, path_file: str, ntlmv2_collected: dict):
        super().__init__(path_file, ntlmv2_collected, alerts_dictionary)

    def emit(self, record):
        level, depth = super().emit(record)
        logger.opt(depth=depth, exception=record.exc_info).log(
            level, record.getMessage()
        )


class InterceptHandlerNtlmRelay(logging.Handler):
    def __init__(self, alerts_dictionary: dict) -> None:
        super().__init__()
        self.__alerts_dictionary = alerts_dictionary

    def emit(self, record: LogRecord) -> Tuple[str, int]:
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
        print(type(record))
        return level, depth


class InterceptHandlerStdoutNtlmRelay(InterceptHandlerNtlmRelay):
    def __init__(self, alerts_dictionary: dict = None) -> None:
        super().__init__(alerts_dictionary)

    def emit(self, record: LogRecord) -> None:
        level, depth = super().emit(record)
        if level == "INFO":
            logger.bind(name="info").opt(depth=depth, exception=record.exc_info).log(
                level, record.getMessage()
            )
        elif level != "DEBUG":
            logger.bind(name="error").opt(depth=depth, exception=record.exc_info).log(
                level, record.getMessage()
            )


class InterceptHandlerOnlyFilesNtlmRelay(InterceptHandlerNtlmRelay):
    def __init__(self, alerts_dictionary) -> None:
        super().__init__(alerts_dictionary)
        self.__alerts_dictionary = alerts_dictionary

    def emit(self, record: LogRecord) -> None:
        level, depth = super().emit(record)
        if "Done dumping SAM hashes for host:" in record.getMessage():
            self.__alerts_dictionary["sam_dump"] = 1

        if "Enjoy" in record.getMessage():
            self.__alerts_dictionary["new_connection"] = 1

        logger.opt(depth=depth, exception=record.exc_info).log(
            level, record.getMessage()
        )
