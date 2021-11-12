from loguru import logger
import logging
import cmd2
import sys
import os

# https://stackoverflow.com/questions/65329555/standard-library-logging-plus-loguru
class InterceptHandlerStdoutMss(logging.Handler):

    def __init__(self,path_file:str ,ntlmv2_collected:list):
        super().__init__()
        self.__path_file = path_file
        self.__ntlmv2_collected = ntlmv2_collected

    def __open_the_file(self, message: str) -> None:
        file_created = f"{self.__path_file}/ntlmv2_hashes.txt"
        if os.path.exists(file_created):
            with open(file_created, "a") as output_file:
                output_file.write(message+"\n")
        else:
            with open(file_created, "w") as output_file:
                output_file.write(message+"\n")

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

        logger.bind(name="info").info(self.__ntlmv2_collected)
        if (
            "::" in record.getMessage()
            and record.getMessage() not in self.__ntlmv2_collected
        ):
            self.__ntlmv2_collected.append(record.getMessage())
            self.__open_the_file(record.getMessage())


class InterceptHandlerOnlyFilesMss(logging.Handler):
    def __init__(self, alerts_dictionary: dict, ntlmv2_collected: list, path_file: str):
        super().__init__()
        self.__alerts_dictionary = alerts_dictionary
        self.__ntlmv2_collected = ntlmv2_collected
        self.__path_file = path_file

    def __open_the_file(self, message: str) -> None:
        file_created = f"{self.__path_file}/nlvm2_hashes.txt"
        if os.path.exists(file_created):
            with open(file_created, "a") as output_file:
                output_file.write(message)
        else:
            with open(file_created, "w") as output_file:
                output_file.write(message)

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
            self.__open_the_file(record.getMessage())

        logger.opt(depth=depth, exception=record.exc_info).log(
            level, record.getMessage()
        )


class InterceptHandlerStdoutNtlmRelay(logging.Handler):
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
