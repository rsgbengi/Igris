#!/usr/bin/env python
# -*- coding: utf-8 -*-

import ipaddress
from logging import Logger
from typing import List

import os
import sys
import re
import cmd2
import netifaces
from cmd2 import ansi
from art import text2art
from loguru import logger
from log_symbols import LogSymbols
from rich.console import Console
from rich.table import Table
from .load import Load
from ..utils import ScanForPsexec, Psexec
from .attackstatus import AttackStatus
from ..network import SmbServerAttack, NtlmRelay, DNSTakeOverCommand, PoisonCommand
from ..utils import Neo4jConnection
from ..dashboard import DashboardCommand


COLORS = {
    "black": "\u001b[30;1m",
    "red": "\u001b[31;1m",
    "blackred": "\u001b[39;1m",
    "green": "\u001b[32m",
    "yellow": "\u001b[33;1m",
    "blue": "\u001b[34;1m",
    "magenta": "\u001b[35m",
    "cyan": "\u001b[36m",
    "white": "\u001b[37m",
    "yellow-background": "\u001b[43m",
    "black-background": "\u001b[40m",
    "cyan-background": "\u001b[46;1m",
}


class Igris_Shell(cmd2.Cmd):
    def __init__(self):
        super().__init__(
            auto_load_commands=False,
            persistent_history_file="save/history.json",
        )
        # Configure settable variables
        self.__credentials_config_variables()
        self.__network_config_variables()
        # Defect for intro messsage
        self.intro = self.__banner() + "\n" + text2art("Igris Shell")

        self.__path = ""
        self._set_prompt()
        # Options
        self.allow_style = ansi.STYLE_TERMINAL

        self.__set_up_file_loggers()
        self.__error_logger = None
        self.__info_logger = None
        self.__id_error_logger = None
        self.__id_info_logger = None
        self.register_precmd_hook(self.__set_up_output_loggers)

        self.load_modules()
        self.__before_end_methods()
        # Enabled Attacks
        self.__configure_enabled_attacks()

        # configure database
        self.__init_databse()

    @property
    def info_logger(self) -> Logger:
        return self.__info_logger

    @property
    def error_logger(self) -> Logger:
        return self.__error_logger

    @property
    def active_attacks(self) -> None:
        return self.__active_attacks

    def __init_databse(self) -> None:
        """[Method to initialize the connection to the database]"""
        self.igris_db = Neo4jConnection(
            "neo4j://localhost:7687",
            "neo4j",
            "igris",
        )

    def active_attacks_status(self, attack: str) -> bool:
        """[Method to see if an attack is activated or not]

        Args:
            attack (str): [Specific attack]

        Returns:
            bool: [ State of lataque selecting ]
        """
        return self.__active_attacks[attack]

    def active_attacks_configure(self, attack: str, status: bool) -> None:
        """[ Method to change the status of a command ]

        Args:
            attack (str): [ Selected attack ]
            status (bool): [ True of false depending on the state ]
        """
        self.__active_attacks[attack] = status

    def __configure_enabled_attacks(self) -> None:
        """[ Method to configure the enble attacks]"""

        self.__active_attacks = {
            "MDNS_Poisoning": False,
            "LLMNR_Poisoning": False,
            "NBT_NS_Poisoning": False,
            "DNS_Poisoning": False,
            "DHCP6_Rogue": False,
            "MSS": False,
            "NTLM_Relay": False,
        }

    def __before_end_methods(self):
        """[Method to establish which functions will be executed before the shell ends]"""
        self.register_postloop_hook(self.__ntlm_relay_module.ntlm_relay_postloop)
        self.register_postloop_hook(self.__mss_module.mss_postloop)
        self.register_postloop_hook(self.__scan_module.scan_postloop)

        self.register_postloop_hook(self.__poison_module.poison_postloop)

        self.register_postloop_hook(self.__dnstakeover_module.dnstakeover_postloop)

    def load_modules(self) -> None:
        """[ Function to activate the available modules ]"""
        self.__scan_module = ScanForPsexec()
        self.__psexec_module = Psexec()
        self.__ntlm_relay_module = NtlmRelay()
        self.__mss_module = SmbServerAttack()
        self.__poison_module = PoisonCommand()
        self.__dnstakeover_module = DNSTakeOverCommand()
        self.__process_status = AttackStatus()
        self.__dashboard = DashboardCommand()

        self.register_command_set(self.__psexec_module)
        self.register_command_set(self.__scan_module)
        self.register_command_set(self.__ntlm_relay_module)
        self.register_command_set(self.__mss_module)
        self.register_command_set(self.__dnstakeover_module)
        self.register_command_set(self.__poison_module)
        self.register_command_set(self.__process_status)
        self.register_command_set(self.__dashboard)

    def __credentials_config_variables(self):
        """[ Settable Variables for credentials ]"""
        # User
        self.USER = "Administrator"
        self.add_settable(cmd2.Settable("USER", str, "Set user target", self))

        # Password aad3b435b51404eeaad3b435b51404ee:c39f2beb3d2ec06a62cb887fb391dee0
        self.PASSWD = "P@$$w0rd!"
        self.add_settable(
            cmd2.Settable(
                "PASSWD",
                str,
                "Set password of the target. It could be ntlm hash to perform pass the hash",
                self,
            )
        )

    def __network_config_variables(self):
        """[ Settable variables for network ]"""
        # Set LHOST option
        self.LHOST = "192.168.253.135"
        self.add_settable(cmd2.Settable("LHOST", str, "Set ip of your machine", self))

        # Set SUBNET option
        self.SUBNET = "192.168.253.0/24"
        self.add_settable(cmd2.Settable("SUBNET", str, "Set subnet target", self))

        # IP_TARGET
        self.RHOST = "192.168.253.138"
        self.add_settable(cmd2.Settable("RHOST", str, "Set ip of the target", self))

        self.INTERFACE = "ens33"
        self.add_settable(
            cmd2.Settable("INTERFACE", str, "Set interface to sniff packets", self)
        )
        self.MAC_ADDRESS = "00:0c:29:0e:d7:3b"
        self.add_settable(
            cmd2.Settable("MAC_ADDRESS", str, "Set mac address of your interface", self)
        )
        self.LPORT = "445"
        self.add_settable(cmd2.Settable("LPORT", str, "Set local port", self))

        self.IPV6 = "fe80::20c:29ff:fe0e:d73b"
        self.add_settable(
            cmd2.Settable("IPV6", str, "Set the IPV6 of the target", self)
        )

    def _set_prompt(self) -> None:
        """[Function that will set the command line format]"""
        self.__path = os.getcwd()
        self.prompt = ansi.style("Igris shell -> ", fg=ansi.fg.blue) + ansi.style(
            f"{self.__path} ", fg=ansi.fg.cyan
        )

    def postcmd(self, stop: bool, line: str) -> bool:
        """[ Hook method executed just after a command dispatch is finished ]

        Args:
            stop (bool): [return True to request the command loop terminate]
            line (str): [ input of the user ]

        Returns:
            bool: [ True if the user use the command 'quit' ]
        """
        self._set_prompt()
        return stop

    @cmd2.with_argument_list
    def do_cd(self, args: List[str]) -> None:
        """Change the directoy.
        Usage:
            cd <new_dir>
        """
        if not args or len(args) != 1:
            self.__error_logger.error("cd needs one argument:")
            self.do_help("cd")
            return

        path_to_change = os.path.abspath(args[0])

        error = None
        if not os.path.isdir(path_to_change):
            error = f"{path_to_change} is not a directory"
        elif not os.access(path_to_change, os.R_OK):
            error = f"You do not have read access to {path_to_change}"
        else:
            try:
                os.chdir(path_to_change)
            except Exception as exception:
                error = exception
        if error:
            self.__error_logger.error(error)

    def complete_cd(self, text: str, line: str, begidx: int, endidx: int) -> List[str]:
        """[ Allow  user auto-complete when using cd ]

        Args:
            text (str): [ The string prefix we are attempting to match]
            line (str): [ the current input line with leading whitespace removed]
            begidx (int): [ The beginning index of the prefix text]
            endidx (int): [ the ending index of the prefix text]

        Returns
            List[str] : [ A list of possible tab completions ]
        """
        return self.path_complete(text, line, begidx, endidx, path_filter=os.path.isdir)

    def check_settable_variables_value(self, necessary_settable: dict[str]) -> bool:
        """[ Function that checks if the settable variables value don't have an empty value ]

        Args:
            necessary_settable (dict[str]): [ Dictionary with all settable variables used by the calling funcition ]

        Returns:
            bool: [ Returns if all variables are correct ]
        """
        self.__info_logger.debug(
            "Checking the correct value of the necessary settable variables "
        )
        for settable_name, settable_value in necessary_settable.items():
            if settable_value == "":
                self.__error_logger.error(
                    f"The settable variable {settable_name} is not initialized. Run the command with -SS to show Settable variables"
                )
                self.__error_logger.error(f"Missing settable variable: {settable_name}")
                return False
        return True

    def show_settable_variables_necessary(
        self, necessary_settable_variables: dict[str]
    ) -> None:
        """[  Show all settable variables that will be needed in the calling command ]

        Args:
            necessary_settable_variables (dict[str]): [  Dictionary with all settable variables used by the calling funcition ]
        """
        self.__info_logger.info("Showing necessary settable variables")
        console = Console()
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Variable")
        table.add_column("Value")

        for variable, value in necessary_settable_variables.items():
            table.add_row(f"[blue]{variable}[/blue]", f"[bold cyan]{value}[/bold cyan]")
        console.print(table)

    def __color_text(self, text: str) -> str:
        """[ Function that will color the banner ]

        Args:
            text (str): [ Text to be colored ]

        Returns:
            str : [ Colored text ]
        """
        for color in COLORS:
            text = text.replace(f"[[{color}]]", COLORS[color])
        return text

    def __banner(self) -> str:
        """[ Function to prepare the banner ]"""
        logo = """
        [[black]] _____[[black]]__▄____________    
        [[black]]_____[[black]]_█▀╓▄▄▄[[red]]▓▓▄µ [[black]]___ [[blue]]
        [[black]]___ç [[black]]║███████[[red]]██▓▓¿[[black]]__ [[blue]] 
        [[black]] ___[[black]]╙███████████[[red]]▓▓▓▄[[black]]_
        [[black]]_____[[blue]]╠█[[black]]██[[blue]]▀[[black]]███╜_[[red]]█▓▓█▌
        [[black]]______[[black]]██████__ [[red]]╙█▓██
        [[black]]_____[[blue]],▄▄▀░╔▓▄▓,_[[red]]▓███
        [[black]]_____[[black]]"█▌[[blue]]▓▓▓▓[[black]]██▀_[[red]]▐███
        [[black]]_____[[black]]╓███████▌___[[red]]██M
        [[black]] _____[[black]]ⁿ████████N__[[red]]▐▀[[black]]_
        [[black]]▐█▄▄██████████▌__'__
        [[black]] _[[red]]▀██[[black]]██████████[[red]]██▓M[[black]]__
        [[black]] ___[[red]]└▀█▓▓▓▓▓▓█▀╩[[black]]_____
        [[black]] _____[[red]]"╫▓▓██▓"[[black]]_______
        [[black]] ________[[red]]½[[black]]__________
        [[blue]]
        """
        return self.__color_text(logo)

    def __check_ip(self, ip: str, name: str) -> bool:
        """[ Method to check if the value of an ip is valid]

        Args:
            ip (str): [ Ip to check]
            name (str): [ Name of the error to report ]

        Returns:
            bool: [ Status of the ip ]
        """
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            self.error_logger.error(f"Not valid {name}")
            return False
        return True

    def __check_mac(self) -> bool:
        """[ Method to check that the value of the mac_address is valid]

        Returns:
            bool: [ Evaluation of the check ]
        """
        if not re.match(
            "[0-9a-f]{2}([-:])[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", self.MAC_ADDRESS.lower()
        ):
            self.error_logger.error("Not valid mac address")
            return False
        return True

    def __check_interface(self) -> bool:
        """[ Method to check the value of the interface ]

        Returns:
            bool: [ Returns if the interface is in the possible interfaces ]
        """
        if self.INTERFACE not in netifaces.interfaces():
            self.error_logger.error("The interface is not valid")
            return False
        return True

    def __check_port(self, number: str) -> bool:
        """[ Method to check if the port number is valid]

        Args:
            number (str): [ The port number]

        Returns:"
            bool: [ True if the port number is correct ]
        """
        if not number.isnumeric():
            self.error_logger.error("The port must be a number")
            return False
        if int(number) < 0 or int(number) > 65535:
            self.error_logger.error("Not valid port number. Must be 0-65535")
            return False
        return True

    def __check_subnet(self) -> bool:
        try:
            ipaddress.IPv4Network(self.SUBNET)
        except ipaddress.AddressValueError:
            self.error_logger.error(
                "Error with the subnet value. Example of correct subnet: 192.168.253.0/24.Use -SS to see the value."
            )
            return False
        return True

    def _check_configurable_variables(self, variables: dict) -> bool:
        """[ Method to check the value of settable variables ]

        Args:
            variables (dict): [ variables used in a command ]

        Returns:
            bool: [ Method evaluation ]
        """
        correct_value = True
        for key in variables:
            if key == "LHOST":
                correct_value = self.__check_ip(self.LHOST, "LHOST")
            if key == "RHOST":
                correct_value = self.__check_ip(self.RHOST, "RHOST")
            if key == "LPORT":
                correct_value = self.__check_port(self.LPORT)
            if key == "SUBNET":
                correct_value = self.__check_subnet()
            if key == "MAC_ADDRESS":
                correct_value = self.__check_mac()
            if key == "INTERFACE":
                correct_value = self.__check_interface()
            if not correct_value:
                return correct_value
        return correct_value

    def __set_up_file_loggers(self) -> None:
        """[ Method to configure the files where the log messages will be saved ]"""
        logger.add(
            "logs/all.log",
            level="DEBUG",
            rotation="1 week",
            enqueue=True,
        )
        logger.add(
            "logs/info_above.log",
            level="INFO",
            rotation="1 week",
            enqueue=True,
        )

    def __set_up_output_loggers(
        self, data: cmd2.plugin.PrecommandData
    ) -> cmd2.plugin.PrecommandData:
        """[ Function to prepare the logger ]"""
        # export LOGURU_AUTOINIT=False

        if self.__id_info_logger is not None:
            logger.remove(self.__id_info_logger)
        if self.__id_error_logger is not None:
            logger.remove(self.__id_error_logger)

        logger.level("DEBUG", icon=LogSymbols.INFO.value)
        logger.level("SUCCESS", icon=LogSymbols.SUCCESS.value)
        logger.level("INFO", icon=LogSymbols.INFO.value)
        logger.level("WARNING", icon=LogSymbols.WARNING.value)
        logger.level("ERROR", icon=LogSymbols.ERROR.value)
        fmt = "{level.icon} {message}"
        self.__id_info_logger = logger.add(
            sink=self.stdout,
            level="INFO",
            format=fmt,
            filter=lambda record: record["extra"].get("name") == "info",
        )

        self.__id_error_logger = logger.add(
            sink=sys.stderr,
            level="WARNING",
            format=fmt,
            filter=lambda record: record["extra"].get("name") == "error",
        )
        self.__info_logger = logger.bind(name="info")
        self.__error_logger = logger.bind(name="error")
        return data
