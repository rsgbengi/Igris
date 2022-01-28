import argparse
import concurrent.futures
import functools
from ipaddress import IPv4Address, IPv4Network
import ntpath
import random
from rich.console import Console
from rich.table import Table
import json


from halo import Halo
from typing import Tuple
import cmd2
import pandas as pd
from cmd2 import CommandSet, ansi, with_default_category
from impacket.smb import SMB_DIALECT
from impacket.smbconnection import SMBConnection
from log_symbols import LogSymbols
from spinners.spinners import Spinners
from tabulate import tabulate

from spnego._ntlm_raw.crypto import is_ntlm_hash
from .gatherinfo import TargetInfo, UserInfo, SubnetInfo
from multiprocessing import Process, Manager, managers
import pickle


@with_default_category("Utilities")
class ScanForPsexec(CommandSet):
    def __init__(self):
        super().__init__()
        self.__parse_json()
        self.__spinner_list = [key.name for key in Spinners]
        self.__spinner = None
        self.__scan_process = None

    def scan_postloop(self) -> None:
        """[Function that will be performe when the user exits the shell]"""
        if self.__is_running():
            self._cmd.info_logger.info(
                ansi.style(
                    "The scan process must finished before exit...",
                    fg=ansi.fg.bright_yellow,
                )
            )
            self.__scan_process.terminate()
            self.__scan_process.join()
            self._cmd.info_logger.success(
                ansi.style("The scan has finished", fg=ansi.fg.bright_green)
            )
            self.__save_state()

    def __parse_json(self):
        try:
            f = open("/home/rsgbengi/Igris/save/scan", "rb")
            self.__scan_info = pickle.load(f)
            for subnet in self.__scan_info.values():
                subnet.casting_to_manager_list_computers()
        except FileNotFoundError:
            self.__scan_info = {}

    def __try_scan_connection_with_smb1(
        self, ip: IPv4Address
    ) -> Tuple[bool, SMBConnection]:
        """[This function will try to connect to a remote host
            using smb1]

        Args:
            ip (IPv4Address): [ip of the remote host]

        Returns:
            Tuple[bool, SMBConnection]: [Returns the state of the connection and the variable to manipulate the connection]
        """
        succeed_in_connection = False
        smbclient = None
        try:
            smbclient = SMBConnection(
                str(ip), str(ip), timeout=1, preferredDialect=SMB_DIALECT
            )

            self._cmd.info_logger.debug(f"Connection success using smb1 at {ip}")
            succeed_in_connection = True
        except Exception:  # SessionError not working as expected
            self._cmd.info_logger.debug(f"Connection fails using smb1 at {ip}")

        return succeed_in_connection, smbclient

    def __try_scan_connection_with_smb3(
        self, ip: IPv4Address
    ) -> Tuple[bool, SMBConnection]:
        """[This function will try to connect to a remote host
            using smb3]
        Args:
            ip (IPv4Address): [ip of the remote host]

        Returns:
            Tuple[bool, SMBConnection]: [Returns the state of the connection and the variable to manipulate the connection]
        """

        succeed_in_connection = False
        smbclient = None
        try:
            smbclient = SMBConnection(str(ip), str(ip), timeout=1)
            succeed_in_connection = True
            self._cmd.info_logger.debug(f"Connection success using smb3 at {ip}")
        except Exception:
            self._cmd.info_logger.debug(f"Connection fails using smb3 at {ip}")

        return succeed_in_connection, smbclient

    def __check_scan_login_possibility(
        self, user_info: UserInfo, smbclient: SMBConnection
    ) -> bool:
        """[Function to know if a user can log in]

        Args:
            user_info (UserInfo): [User info needed to login to the remote
                                        machine(user,password)]
            smbclient (SMBConnection): [Argument to manipulate the smb
                                            connection, in this case is use
                                            to perform the login]
        Returns:
            bool : [variable to notify login status]

        """

        succeed_in_login = False
        user = user_info.user
        password = user_info.passwd
        ip = smbclient.getRemoteName()
        nt = None
        lm = None

        try:
            if is_ntlm_hash(password):
                lm, nt = password.split(":")
                smbclient.login(user, password="", lmhash=lm, nthash=nt)
            else:
                smbclient.login(user, password)
            succeed_in_login = True
            self._cmd.info_logger.debug(f"Login successful at {ip}")
        except Exception:
            self._cmd.info_logger.debug(f"Login successful at {ip}")
        return succeed_in_login

    def __configure_target_info_of_scan(
        self, target_info: TargetInfo, smbclient: SMBConnection, subnet: str
    ) -> None:
        """[Function to set different values of smbclient into TargetInfo object]

        Args:
            target_info (TargetInfo): [Argument to set information contained
                                            in smbclient]
            smbclient (SMBConnection): [Argument that contains all information about
                                    the current smb connection]
        """
        ip = smbclient.getRemoteName()
        self._cmd.info_logger.debug(
            f"Loading target info of {smbclient.getServerName()} at {ip}"
        )
        target_info.signed = smbclient.isSigningRequired()
        target_info.computer_name = smbclient.getServerName()
        target_info.os = smbclient.getServerOS()
        target_info.subnet = subnet

    def __check_psexec_possibility(self, smbclient: SMBConnection) -> bool:
        """[Function that checks ifa user could do psexec listing the contents
                of the admin folder]

        Args:
            smbclient (SMBConnection): [Object with the current smb connection]

        Returns:
            bool : [Returns whether the user can do psexec ]
        """
        success_in_psexec = False
        ip = smbclient.getRemoteName()
        try:
            smbclient.listPath("ADMIN$", ntpath.normpath("\\*"))
            success_in_psexec = True
            self._cmd.info_logger.debug(
                f"Possibility of psexec on {smbclient.getServerName()} at {ip}"
            )
        except Exception:
            self._cmd.info_logger.debug(
                f"Error of psexec on {smbclient.getServerName()} at {ip}"
            )

        return success_in_psexec

    def __show_user_passwd(self) -> None:
        """[Shows the user and password content of the settable variables]"""
        user = self._cmd.USER
        passwd = self._cmd.PASSWD

        self._cmd.poutput(
            ansi.style("USER -> ", fg=ansi.fg.red) + ansi.style(user, fg=ansi.fg.blue)
        )
        self._cmd.poutput(
            ansi.style("PASSWD -> ", fg=ansi.fg.red)
            + ansi.style(passwd, fg=ansi.fg.blue)
        )

    def __show_subnet_information(self) -> None:
        """[Shows the information of a specific subnet]"""
        console = Console()
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("IP")
        table.add_column("Operating System")
        table.add_column("Psexec")
        table.add_column("Computer Name")
        table.add_column("Signed")
        for computer in self.__scan_info[self._cmd.SUBNET].computers:
            user_status = computer.users[self._cmd.USER + self._cmd.PASSWD]
            table.add_row(
                f"[blue]{computer.ip}[/blue]",
                f"[cyan]{computer.os}[/cyan]",
                f"[yellow]{user_status.psexec_info()}[/yellow]",
                f"[cyan]{computer.computer_name}[/cyan]",
                f"[cyan]{computer.signed}[/cyan]",
            )
        console.print(table)

    def __show_scan_info(self) -> None:
        """[Function that will check if it is possible to display the scan
        info of a current username and password]
        """
        subnet = self._cmd.SUBNET

        self._cmd.poutput(
            ansi.style("SUBNET -> ", fg=ansi.fg.red)
            + ansi.style(subnet, fg=ansi.fg.blue)
        )
        if (
            self._cmd.igris_db.check_if_subnet_exits(subnet)
            and self._cmd.igris_db.number_of_computers_collected(subnet) != 0
            and self._cmd.igris_db.check_if_match_user_subnet_exits(
                self._cmd.USER, self._cmd.PASSWD, subnet
            )
        ):
            self.__show_subnet_information()
        else:
            self._cmd.error_logger.warning(
                f"the analysis of this {subnet} has not collected any information or no scan has been performed with it yet"
            )

    def __configure_users_used(self, user: UserInfo, subnet: str) -> bool:
        """[Function that will configure the users used used]

        Returns:
            bool : [Returns if the scan can continue]
        """
        continue_operations = True
        user_has_been_used = self._cmd.igris_db.init_user_used_in_a_subnet(
            user.user, user.passwd, subnet
        )
        if user_has_been_used:
            answer = input(
                "This user and password have been used before. Do you want to repeat the scan ?"
            )
            continue_operations = answer == ("y" or "Y")

        return continue_operations

    def __configure_scan_info(self) -> bool:
        """[Function that will configure the dictionary scan_info to do the scan]

        Returns:
            bool : [Returns if the scan can continue]
        """

        user = self._cmd.USER
        passwd = self._cmd.PASSWD
        subnet = self._cmd.SUBNET

        user = UserInfo(user, passwd)
        continue_operations = True
        if not self._cmd.igris_db.check_if_subnet_exits(subnet):
            self._cmd.igris_db.init_new_subnet(subnet)
        #continue_operations = self.__configure_users_used(user, subnet)
        return continue_operations

    def __check_conectivity_of_scan(
        self, user_info: UserInfo, subnet: str, ip: IPv4Address
    ) -> Tuple[bool, TargetInfo, SMBConnection]:
        """[Function to check if the connectivity to a specific remote host is possible]

        Args:
            user_info (UserInfo): [Argument that contains values needed for
                                        login]
            subnet (str): [Target subnet to do the scan ]
            ip (IPv4Address): [Ip of the current machine that the scan is analizing]

        Returns:
            Tuple [bool, TargetInfo, SMBConnection]: [ Returns the statuts of the connection  with
                                                        information collected from the target]
        """

        possibility_of_login = False
        target_info = None

        conn_with_smb_dialect, smbclient = self.__try_scan_connection_with_smb1(ip)
        if not conn_with_smb_dialect:
            conn_without_smb_dialect, smbclient = self.__try_scan_connection_with_smb3(
                str(ip)
            )

        if conn_with_smb_dialect or conn_without_smb_dialect:
            target_info = TargetInfo(str(ip), subnet, user_info)
            possibility_of_login = self.__check_scan_login_possibility(
                user_info, smbclient
            )

        return possibility_of_login, target_info, smbclient

    def __set_up_scan_results(
        self,
        smbclient: SMBConnection,
        target_info: TargetInfo,
        user_info: UserInfo,
        subnet: str,
    ) -> None:
        """[Prepare everything to later show the saved information of the connection
                asynchronously]

        Args:
            smbclient (SMBConnection): [Object with the current smb connection]
            target_info (targetinfo): [object that contains info of the current target]
        """
        self.__configure_target_info_of_scan(target_info, smbclient, subnet)
        success_in_psexec = self.__check_psexec_possibility(smbclient)
        target_info.psexec = success_in_psexec
        self._cmd.igris_db.create_computer_node(target_info, user_info)

    def __is_user_in_admin_group_asynchronous(
        self, user_info: UserInfo, subnet: str, ip: IPv4Address
    ) -> None:
        """[Function that is used to know if the user is an administrator and
                is currently able to psexec(asynchronous way)]

        Args:
            user_info (UserInfo): [User info needed to know user privileges]
            subnet (str): [Target subnet to scan]
            ip (IPv4Address): [Ip target of the current remote host]
        """
        (
            possibility_of_login,
            target_info,
            smbclient,
        ) = self.__check_conectivity_of_scan(user_info, subnet, ip)
        if possibility_of_login:
            self.__set_up_scan_results(smbclient, target_info, user_info, subnet)
        if smbclient is not None:
            smbclient.close()

    def __set_up_scan_actions_asynchronous(self) -> None:
        """[Prepare everything to scan asynchronously  using threads]"""
        user = self._cmd.USER
        password = self._cmd.PASSWD
        subnet = self._cmd.SUBNET
        user_info = UserInfo(user, password)

        with concurrent.futures.ThreadPoolExecutor() as executor:
            executor.map(
                functools.partial(
                    self.__is_user_in_admin_group_asynchronous, user_info, subnet
                ),
                IPv4Network(subnet),
            )

        if self._cmd.terminal_lock.acquire(blocking=False):
            self._cmd.async_alert(
                ansi.style(
                    LogSymbols.SUCCESS.value + " The scan has finished!",
                    fg=ansi.fg.green,
                )
            )
            self._cmd.terminal_lock.release()
        self._cmd.info_logger.debug("Asynchronous scanning has been completed.")

    def __asynchronous_way(self) -> None:
        """[Function that will start the asynchronous scan]"""
        self._cmd.info_logger.info("Using asynchronous scan.")
        self._cmd.info_logger.info(
            ansi.style(
                "Starting... The messeges will be displayed as new computer is found",
                fg=ansi.fg.green,
            )
        )

        self.__scan_process = Process(target=self.__set_up_scan_actions_asynchronous)
        self.__scan_process.start()

    def __show_scan_results_synchronous(self, target_info: TargetInfo) -> None:
        """[Display the results of an synchronous scan]

        Args:
            target_info (TargetInfo): [Contains all the info to be displayed]
        """
        os = target_info.os
        ip = target_info.ip
        ip_with_color = ansi.style(ip, fg=ansi.fg.blue)
        os_with_color = ansi.style(os, fg=ansi.fg.cyan)
        if target_info.psexec:
            admin = ansi.style(target_info.psexec_info(), fg=ansi.fg.yellow)
            self.__spinner.warn(admin + " " + os_with_color + " " + ip_with_color)
        else:
            self.__spinner.info(" " + os_with_color + " " + ip_with_color)

        self.__spinner.start()

    def __is_user_in_admin_group_synchronous(
        self, user_info: UserInfo, subnet: str, ip: IPv4Address
    ) -> TargetInfo:
        """[Function that is used to know if the user is an administrator and
                is currently able to psexec(synchronous way)]

        Args:
            user_info (UserInfo): [User info needed to know user privileges]
            subnet (str): [Target subnet to scan]
            ip (IPv4Address): [Ip target of the current remote host]

        Returns:
            TargetInfo: [ Returns the target information ]
        """

        self.__spinner.text = "Working in " + str(ip)
        (
            possibility_of_login,
            target_info,
            smbclient,
        ) = self.__check_conectivity_of_scan(user_info, subnet, ip)
        if possibility_of_login:
            self.__set_up_scan_results(smbclient, target_info, user_info, subnet)
        if smbclient is not None:
            smbclient.close()
        return target_info

    def __set_up_spinner(self) -> None:
        number_of_spinner_possibilities = len(self.__spinner_list)
        number_of_spinner_selected = random.randrange(number_of_spinner_possibilities)

        self.__spinner = Halo(
            text="Loading...",
            spinner=self.__spinner_list[number_of_spinner_selected],
            stream=self._cmd.stdout,
        )
        self.__spinner.start()

    def __set_up_scan_actions_synchronous(self) -> None:
        """[Prepare everything to scan synchronously  using threads]"""

        user = self._cmd.USER
        password = self._cmd.PASSWD
        subnet = self._cmd.SUBNET
        user_info = UserInfo(user, password)
        self.__set_up_spinner()

        with concurrent.futures.ThreadPoolExecutor() as executor:
            try:
                results = executor.map(
                    functools.partial(
                        self.__is_user_in_admin_group_synchronous, user_info, subnet
                    ),
                    IPv4Network(subnet),
                )
                for target_info in results:
                    if (
                        (target_info is not None)
                        and (target_info.os is not None)
                        and (target_info.ip is not None)
                    ):
                        self.__show_scan_results_synchronous(target_info)
            except KeyboardInterrupt:
                executor.shutdown()
                self._cmd.error_logger.warning("\nExiting ...")
                self._cmd.info_logger.debug("The scan was interrupted")
        self.__spinner.stop()
        self._cmd.info_logger.success("Synchronous scanning has been completed")

    def __synchronous_way(self) -> None:
        """[ Function that will start the synchronous scan]"""

        self._cmd.info_logger.info("Using synchronous scan")

        synchronous_scan_process = Process(
            target=self.__set_up_scan_actions_synchronous
        )
        synchronous_scan_process.start()
        try:
            synchronous_scan_process.join()
        except KeyboardInterrupt:
            synchronous_scan_process.terminate()
            synchronous_scan_process.join()
            self._cmd.poutput("\n")

    def __save_state(self):
        for subnet in self.__scan_info.values():
            subnet.casting_to_list_computers()
        with open("/home/rsgbengi/Igris/save/scan", "wb") as outfile:
            pickle.dump(self.__scan_info, outfile)

    def __start_scan(self, args: argparse.Namespace) -> None:
        """[ Start scan of the subnet ]

        Args:
            args (argparse.Namespace): [ Arguments passed to the scan command ]
        """

        continue_operations = self.__configure_scan_info()
        print(continue_operations)
        if continue_operations:

            self._cmd.info_logger.info("Starting to launch threads based on your cpu")
            if args.asynchronous:
                self.__asynchronous_way()
            else:
                self.__synchronous_way()
                self.__save_state()

    def __end_scan(self) -> None:
        """[ Process to finished the scan process ]"""
        if self.__is_running:
            self._cmd.error_logger.warning("Exiting ...")
            self.__scan_process.terminate()
            self.__scan_process.join()
            self.__save_state()

    def __is_running(self) -> None:
        """[ Method to check if the scan is already in progress ]"""
        return self.__scan_process is not None and self.__scan_process.is_alive()

    def __check_conditions_for_the_attack(self, args: argparse.Namespace) -> bool:
        if args.show_info:
            self.__show_scan_info()
            return False
        if args.end_scan:
            self.__end_scan()
            return False
        if self.__is_running():
            self._cmd.error_logger.warning(
                "The scan is already running in the background ..."
            )
            return False
        return True

    argParser = cmd2.Cmd2ArgumentParser(
        description="""Tool to know if there is a possibility to perform psexec. 
        Without arguments this tool will scan the Subnet""",
        epilog="This command is not designed to use pipes(|) or redirections( >< ) when using the scan",
    )
    display_options = argParser.add_argument_group(
        " Arguments for displaying information "
    )
    display_options.add_argument(
        "-SI",
        "--show_info",
        action="store_true",
        help="""It shows the information of all the subnets of the current user 
            and password specified in the settable variables(USER, PASSWD)""",
    )
    display_options.add_argument(
        "-SS",
        "--show_settable",
        action="store_true",
        help="Show Settable variables for this command",
    )

    run_options = argParser.add_argument_group(" Arguments for ways to run a program ")
    run_options.add_argument(
        "-A",
        "--asynchronous",
        action="store_true",
        help="""Run the command asynchronous. To use this functionality, 
        the application must be running in a terminal that supports VT100 
        control characters and readline""",
    )
    run_options.add_argument(
        "-E",
        "--end_scan",
        action="store_true",
        help="Finish the scan in the background",
    )

    @cmd2.with_argparser(argParser)
    def do_scan(self, args: argparse.Namespace) -> None:
        """[Scan command to analyze a subnet in order to find a computer
                that can be psexec]

        Args:
            args (argparse.Namespace): [Arguments passed to the scan command]
        """

        user = self._cmd.USER
        passwd = self._cmd.PASSWD
        subnet = self._cmd.SUBNET

        self._cmd.info_logger.debug(
            f"Starting scan command using user: {user} passwd: {passwd} subnet: {subnet}"
        )

        settable_variables_required = {
            "SUBNET": subnet,
            "USER": user,
            "PASSWD": passwd,
        }
        if not self.__check_conditions_for_the_attack(args):
            return
        if args.show_settable:
            self._cmd.show_settable_variables_necessary(settable_variables_required)
        elif self._cmd.check_settable_variables_value(settable_variables_required):
            self.__start_scan(args)
