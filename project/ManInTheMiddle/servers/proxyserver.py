#!/usr/bin/env python3


from impacket.examples.ntlmrelayx.servers.socksserver import SOCKS
from threading import Thread


class Proxy:
    def __init__(self):
        server = SOCKS()
        server.daemon_threads = True
        server_thread = Thread(target=server.serve_forever)
        server_thread.daemon = True
        server_thread.start()
