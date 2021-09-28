from multiprocessing.context import Process
from impacket import smbserver
import multiprocessing
import signal
import sys


class SmbServer:
    def __init__(self, lhost: str, port: str, output=sys.stdout) -> None:
        self._lhost = lhost
        self._port = port
        self._output = output
        self._server_process = None

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

    def start_smbserver(self) -> None:
        print("Starting smbserver ...", file=self.output)
        server = smbserver.SimpleSMBServer(
            listenAddress=self.lhost, listenPort=int(self.port)
        )
        server.setSMBChallenge("")
        server.start()
