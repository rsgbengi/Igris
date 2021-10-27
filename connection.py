from impacket.examples.ntlmrelayx.servers.socksserver import SOCKS
from threading import Thread
import sys
import os
import logging


class Capturing(list):
    def __enter__(self):
        self._stdout = sys.stdout
        sys.stdout = self._stringio = StringIO()
        return self

    def __exit__(self, *args):
        self.extend(self._stringio.getvalue().splitlines())
        del self._stringio  # free up some memory
        sys.stdout = self._stdout


def hola():
    print("je")


def create_proxy() -> None:
    socksServer = SOCKS()
    socksServer.daemon_threads = True
    socks_thread = Thread(target=socksServer.serve_forever)
    socks_thread.daemon = True
    socks_thread.start()
    allLines = [line for line in stdout.readlines()]
    hola()
    print("hola")


log = logging.getLogger("impacket.examples.ntlmrelayx.servers.sockserver")
print(log)
log.setLevel(logging.ERROR)
create_proxy()
