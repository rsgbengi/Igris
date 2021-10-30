import cmd2
from loguru import logger

try:
    from urllib.request import ProxyHandler, build_opener, Request
except ImportError:
    from urllib2 import ProxyHandler, build_opener, Request


class ntlm_console(cmd2.Cmd):
    def __init__():
        super().__init__()
        self.prompt = "ntlm_shell> "
        self.__url = "http://localhost:9090/ntlmrelayx/api/v1.0/relays"

    def postcmd(self, stop: bool, line: str) -> bool:
        self.prompt = "ntlm_shell> "
        return stop

    def do_show_connections(self):
        try:
            handler = ProxyHandler({})
            open_handler = build_opener(handler)
            response = Request(url)
            r = open_handler.open(response)
            print(items)
        except Exception as e:
            logger.bind(name="error").error("Error when opening connections")
