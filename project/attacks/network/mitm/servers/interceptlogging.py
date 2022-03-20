from loguru import logger
from typing import Tuple
import logging
from logging import LogRecord
import os


class InterceptHandlerMss(logging.Handler):
    """[ Class to intercept log messages and adapt them to the mss attack ]
    Args:
        path_file (str): [ Path to the output file ].
        alerts_dictionary (dict,optional): [  Attribute that contains the dictionary that manages alerts ]. Default to None
    """

    def __init__(self, path_file: str, alerts_dictionary: dict = None) -> None:
        super().__init__()
        self.__path_file = path_file
        self.__alerts_dictionary = alerts_dictionary

    def __open_the_file(self, message: str) -> None:
        """[ Method to create or rewrite the file with the hashes found ]
        Args:
            message (str): [ Intercepted message containing the hash ]
        """

        user = message.split("::")[0]
        file_created = f"{self.__path_file}/{user}_ntlmv2.txt"
        if not os.path.exists(file_created):
            with open(file_created, "w") as output_file:
                output_file.write(message + "\n")

    def __save_hashes(self, message: str) -> None:
        """[ Method to save the new hashes in a file ]
        Args:
            message (str): [ Intercepted message ]
        """
        if "::" in message:
            if self.__alerts_dictionary is not None:
                self.__alerts_dictionary["new_ntlmv2"] = 1
            self.__open_the_file(message)

    def emit(self, record: LogRecord) -> Tuple[str, int]:
        """[ Method that intercepts messages from other loggers ]
        Args:
            record (LogRecord): [ Log with intercepted messages ]
        """
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


class InterceptHandlerStdoutMss(InterceptHandlerMss):
    """[ Class to display intercepted messages on screen ]
    Args:
        path_file (str): [ Path to the output file ].
    """

    def __init__(self, path_file: str) -> None:
        super().__init__(path_file)

    def emit(self, record) -> None:
        """[ Method that intercepts messages from other loggers and display them on the screen ]
        Args:
            record (LogRecord): [ Log with intercepted messages ]
        """
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
    """[ Class to intercept the messages and save them in the log files ]
    Args:
        path_file (str): [ Path to the output file ].
        alerts_dictionary (dict,optional): [  Attribute that contains the dictionary that manages alerts ]. Default to None
    """

    def __init__(self, alerts_dictionary: dict, path_file: str):
        super().__init__(path_file, alerts_dictionary)

    def emit(self, record):
        level, depth = super().emit(record)
        logger.opt(depth=depth, exception=record.exc_info).log(
            level, record.getMessage()
        )


class InterceptHandlerNtlmRelay(logging.Handler):
    """[ Class to intercept messages and adapt them to the ntlm relay attack ]
    Args:
        alerts_dictionary (dict): [  Attribute that contains the dictionary that manages alerts ].
    """

    def __init__(self, alerts_dictionary: dict) -> None:
        super().__init__()

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
        return level, depth


class InterceptHandlerStdoutNtlmRelay(InterceptHandlerNtlmRelay):
    """[ Class to intercept messages and display them on the screen ]
    Args:
        alerts_dictionary (dict,optional): [  Attribute that contains the dictionary that manages alerts ]. Default to None
    """

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
    """[ Class to intercept messages and save them in the log file ]
    Args:
        alerts_dictionary (dict): [  Attribute that contains the dictionary that manages alerts ].
    """

    def __init__(self, alerts_dictionary: dict) -> None:
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
