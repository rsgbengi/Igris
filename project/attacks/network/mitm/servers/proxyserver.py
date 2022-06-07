#!/usr/bin/env python3


from impacket.examples.ntlmrelayx.servers.socksserver import SOCKS
from threading import Thread
from loguru import logger


class Proxy:
    """Class to initialize a SOCKS server to act as a proxy.
    Args:
        info_logger (logger): logger to show information on the screen.
    """

    def __init__(self, info_logger: logger):
        self.__info_logger = info_logger
        self.__info_logger.info("Starting socks server ...")
        self.__server = SOCKS()
        self.__server.daemon_threads = True
        self.__server_thread = Thread(target=self.__server.serve_forever)
        self.__server_thread.daemon = True
        self.__server_thread.start()

    @property
    def server(self) -> SOCKS:
        return self.__server
