#!/usr/bin/env python
# -*- coding: utf-8 -*-

from logging import Logger
from typing import List
import cmd2
import sys
import os
import threading
from cmd2 import ansi
from art import text2art
from tabulate import tabulate
from loguru import logger

from colorama import Fore, Style
from .smb import scan
from .smb import psexec
from .RelayAttacks import SmbRelay
from impacket.examples import logger as log


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
        super().__init__()
        # Set LHOST option
        self.LHOST = "192.168.253.135"
        self.add_settable(cmd2.Settable("LHOST", str, "Set ip of your machine", self))

        # Set SUBNET option
        self.SUBNET = "192.168.253.0/24"
        self.add_settable(cmd2.Settable("SUBNET", str, "Set subnet target", self))

        # User
        self.USER = "Administrator"
        self.add_settable(cmd2.Settable("USER", str, "Set user target", self))

        # Password
        self.PASSWD = "P@$$w0rd!"
        self.add_settable(
            cmd2.Settable("PASSWD", str, "Set password of the target", self)
        )
        # IP_TARGET
        self.IP_TARGET = "192.168.253.134"
        self.add_settable(cmd2.Settable("IP_TARGET", str, "Set ip of the target", self))

        self.INTERFACE = "ens33"
        self.add_settable(
            cmd2.Settable("INTERFACE", str, "Set interface to sniff packets", self)
        )
        self.MAC_ADDRESS = "00:0c:29:89:df:69"
        self.add_settable(
            cmd2.Settable("MAC_ADDRESS", str, "Set mac address of your interface", self)
        )
        self.LPORT = "445"
        self.add_settable(cmd2.Settable("MAC_ADDRESS", str, "Set local port", self))

        self.IPV6 = "fe80::20c:29ff:fe89:df69"
        self.add_settable(
            cmd2.Settable("IPV6", str, "Set the IPV6 of the target", self)
        )

        self.intro = self.banner() + "\n" + text2art("Igris Shell")

        self.path = ""
        self._set_prompt()

        # Options
        self.allow_style = ansi.STYLE_TERMINAL

        self.register_postloop_hook(self.smbmodule_postloop)

        self._scan_thread = threading.Thread()
        self._logger = logger
        self.set_up_loggers()

    @property
    def logger(self) -> Logger:
        return self._logger

    @property
    def scan_thread(self) -> threading.Thread:
        return self._scan_thread

    @scan_thread.setter
    def scan_thread(self, new_thread) -> None:
        self._scan_thread = new_thread

    def smbmodule_postloop(self) -> None:
        """[Function that will be performe when the user exits the shell]"""
        if self.scan_thread.is_alive():
            self.poutput(
                ansi.style(
                    "The scan Thread must finished before exit...",
                    fg=ansi.fg.bright_yellow,
                )
            )
            self.scan_thread.join()
            self.poutput(ansi.style("The thread has finished", fg=ansi.fg.bright_green))

    def _set_prompt(self) -> None:
        """[Function that will set the command line format]"""
        self.path = os.getcwd()
        self.prompt = ansi.style("Igris shell -> ", fg=ansi.fg.blue) + ansi.style(
            self.path + " ", fg=ansi.fg.cyan
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
        if args == [] or len(args) != 1:
            self.perror("cd needs one argument:")
            self.do_help("cd")
            return

        path_to_change = os.path.abspath(args[0])

        error = None
        if not os.path.isdir(path_to_change):
            error = path_to_change + " is not a directory"
        elif not os.access(path_to_change, os.R_OK):
            error = "You do not have read access to " + path_to_change
        else:
            try:
                os.chdir(path_to_change)
            except Exception as exception:
                error = exception
        if error:
            self.perror(error)

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
        self.logger.info(
            "Checking the correct value of the necessary settable variables "
        )
        for settable_name, settable_value in necessary_settable.items():
            if settable_value == "":
                self.perror(
                    f"The settable variable {settable_name} is not initialized. Run the command with -SS to show Settable variables"
                )
                self.logger.error(f"Missing settable variable: {settable_name}")
                return False
        return True

    def show_settable_variables_necessary(
        self, necessary_settable_variables: dict[str]
    ) -> None:
        """[  Show all settable variables that will be needed in the calling command ]

        Args:
            necessary_settable_variables (dict[str]): [  Dictionary with all settable variables used by the calling funcition ]
        """
        self.logger.info("Showing necessary settable variables")
        settable_variables = ansi.style("Variable", fg=ansi.fg.bright_magenta)
        settable_variables_value = ansi.style("Value", fg=ansi.fg.bright_magenta)
        necessary_settable_variables_value_with_color = [
            ansi.style(settable, fg=ansi.fg.blue)
            for settable in necessary_settable_variables.values()
        ]
        necessary_settable_variables_name_with_color = [
            ansi.style(settable, fg=ansi.fg.red)
            for settable in necessary_settable_variables
        ]

        variables = {
            settable_variables: necessary_settable_variables_name_with_color,
            settable_variables_value: necessary_settable_variables_value_with_color,
        }
        self.poutput(tabulate(variables, headers="keys", tablefmt="psql"))

    def color_text(self, text: str) -> str:
        """[ Function that will color the banner ]

        Args:
            text (str): [ Text to be colored ]

        Returns:
            str : [ Colored text ]
        """
        for color in COLORS:
            text = text.replace("[[" + color + "]]", COLORS[color])
        return text

    def banner(self) -> str:
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
        return self.color_text(logo)

    def set_up_loggers(self) -> None:
        """[ Function to prepare the logger ]"""
        # export LOGURU_AUTOINIT=False
        logger.add("logs/all.log", level="DEBUG", rotation="1 week")
        logger.add("logs/info_and_above.log", level="INFO", rotation="1 week")
