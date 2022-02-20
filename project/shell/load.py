#!/usr/bin/env python3

from cmd2.command_definition import with_default_category
from cmd2 import CommandSet, Cmd2ArgumentParser, with_argparser
import argparse
from .utils import ScanForPsexec, Psexec
from .network import SmbServerAttack, NtlmRelay, DNSTakeOverCommand, PoisonCommand
from ..dashboard import DashboardCommand


@with_default_category("Starters")
class LoadUtility(CommandSet):
    def __init__(self) -> None:
        super().__init__()
        self.__scan_module = ScanForPsexec()
        self.__psexec_module = Psexec()
        self.__ntlm_relay_module = NtlmRelay()
        self.__mss_module = SmbServerAttack()
        self.__poison_module = PoisonCommand()
        self.__dnstakeover_module = DNSTakeOverCommand()
        self.__dashboard_command = DashboardCommand()

    argParser = Cmd2ArgumentParser(description="Command to load modules")

    module_options = argParser.add_argument_group("Modules enabled")
    module_options.add_argument(
        "-P",
        "--poison",
        action="store_true",
        help="To load poison attacks",
    )
    module_options.add_argument(
        "-M",
        "--mitm",
        action="store_true",
        help="To load mitm components",
    )

    module_options.add_argument(
        "-U",
        "--utilities",
        action="store_true",
        help="To Load utilities",
    )

    @with_argparser(argParser)
    def do_load(self, args: argparse.Namespace) -> None:
        if args.utilities:
            try:
                self._cmd.register_command_set(self.__psexec_module)
                self._cmd.register_command_set(self.__scan_module)
                self._cmd.register_command_set(self.__dashboard_command)
            except ValueError:
                self._cmd.error_logger_error("Utilities module already loaded")
        if args.network:
            try:
                self._cmd.register_command_set(self.__dnstakeover_module)
                self._cmd.register_command_set(self.__poison_module)
            except ValueError:

                self._cmd.error_logger_error("Poison module already loaded")
        if args.mitm:
            try:
                self._cmd.register_command_set(self.__ntlm_relay_module)
                self._cmd.register_command_set(self.__mss_module)
            except ValueError:

                self._cmd.error_logger_error("Mitm module already loaded")

    argParser = Cmd2ArgumentParser(description="Command to load modules")
    module_options = argParser.add_argument_group("Modules enabled")
    module_options.add_argument(
        "-P",
        "--poison",
        action="store_true",
        help="To load network attacks",
    )
    module_options.add_argument(
        "-M",
        "--mitm",
        action="store_true",
        help="To load mitm components",
    )

    module_options.add_argument(
        "-U",
        "--utilities",
        action="store_true",
        help="To Load utilities",
    )

    def do_unload(self, args: argparse.Namespace) -> None:
        if args.utilities:
            self._cmd.unregister_command_set(self.__psexec_module)
            self._cmd.unregister_command_set(self.__scan_module)
            self._cmd.unregister_command_set(self.__dashboard_command)
            self._cmd.info_logger.info("Utility module unloaded")
        if args.network:
            self._cmd.unregister_command_set(self.__dnstakeover_module)
            self._cmd.unregister_command_set(self.__poison_module)
            self._cmd.error_logger_error("Network module unloaded")
        if args.mitm:
            self._cmd.unregister_command_set(self.__ntlm_relay_module)
            self._cmd.unregister_command_set(self.__mss_module)
