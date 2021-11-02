#!/usr/bin/env python3


from impacket.examples.ntlmrelayx.servers.socksserver import SOCKS
from threading import Thread


class Proxy:
    def __init__(self):
        self.__server = SOCKS()
        self.__server.daemon_threads = True
        self.__server_thread = Thread(target=self.__server.serve_forever)
        self.__server_thread.daemon = True
        self.__server_thread.start()

    @property
    def server(self) -> SOCKS:
        return self.__server
