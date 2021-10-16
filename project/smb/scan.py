import argparse
import concurrent.futures
import functools
from ipaddress import IPv4Address, IPv4Network
import ntpath
import random

from halo import Halo
import threading
from typing import Tuple
import cmd2
import pandas as pd
from cmd2 import CommandSet, ansi, with_default_category
from impacket.smb import SMB_DIALECT
from impacket.smbconnection import SMBConnection
from log_symbols import LogSymbols
from spinners.spinners import Spinners
from tabulate import tabulate

from .gatherinfo import TargetInfo, UserInfo


@with_default_category("SMB Recon")
class ScanForPsexec(CommandSet):
    def __init__(self):
        super().__init__()
        self.__scan_info = {}
        self.__spinner_list = [key.name for key in Spinners]
        self.__spinner = None

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
            self._cmd.info_logger.debug(f"Connection success using smb1 at {ip}")

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
            self._cmd.info_logger.info(f"Connection success using smb3 at {ip}")
        except Exception:
            self._cmd.info_logger.info(f"Connection success using smb3 at {ip}")

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

        try:
            smbclient.login(user, password)
            succeed_in_login = True
            self._cmd.info__logger.info(f"Login successful at {ip}")
        except Exception:
            self._cmd.info_logger.info(f"Login successful at {ip}")
        return succeed_in_login

    def __store_scan_results(self, target_info: TargetInfo) -> None:
        """[Function to store scan results into scan_info dictionary]

        Args:
            target_info (TargetInfo): [Argument that contains all parameters
                                        needed for store the scan results(user,subnet ...)]
        """
        user = target_info.user_info.user
        passwd = target_info.user_info.passwd
        subnet = target_info.subnet
        ip_with_color = target_info.ip
        psexec_possibility = target_info.psexec

        self._cmd.info_logger.debug(f"Saving scan information")

        self.__scan_info[user][passwd][subnet][ip_with_color] = {
            ansi.style("Server Name", fg=ansi.fg.red): target_info.computer_name,
            ansi.style("Operating System", fg=ansi.fg.red): target_info.os,
            ansi.style("Signed", fg=ansi.fg.red): target_info.signed,
        }

        if psexec_possibility:
            admin = ansi.style("PsExec here!", fg=ansi.fg.yellow)
            self.__scan_info[user][passwd][subnet][ip_with_color][
                ansi.style("PsExec", fg=ansi.fg.red)
            ] = admin

    def __configure_target_info_of_scan(
        self, target_info: TargetInfo, smbclient: SMBConnection
    ) -> None:
        """[Function to set different values of smbclient into TargetInfo object]

        Args:
            target_info (TargetInfo): [Argument to set information contained
                                            in smbclient]
            smbclient (SMBConnection): [Argument that contains all information about
                                    the current smb connection]
        """
        ip = smbclient.getRemoteName()
        self._cmd.info_file_logger.info(
            f"Loading target info of {smbclient.getServerName()} at {ip}"
        )
        target_info.signed = smbclient.isSigningRequired()
        target_info.computer_name = smbclient.getServerName()
        target_info.os = smbclient.getServerOS()

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
            self._cmd.info_file_logger.info(
                f"Possibility of psexec on {smbclient.getServerName()} at {ip}"
            )
        except Exception:
            self._cmd.info_logger.info(
                f"Error of psexec on {smbclient.getServerName()} at {ip}"
            )

        return success_in_psexec

    def __show_user_passwd(self) -> None:
        """[Shows the user and password content of the settable variables]"""
        user = self._cmd.USER
        passwd = self._cmd.PASSWD

        self._cmd.info_logger.info(
            ansi.style("USER -> ", fg=ansi.fg.red) + ansi.style(user, fg=ansi.fg.blue)
        )
        self._cmd.info_logger.info(
            ansi.style("PASSWD -> ", fg=ansi.fg.red)
            + ansi.style(passwd, fg=ansi.fg.blue)
        )

    def __show_specific_subnet_info(self, user: str, passwd: str, subnet: str) -> None:
        """[Shows the information of a specific subnet]

        Args:
            user (str): [Current value of the settable variable USER]
            passwd (str): [Current value of the settable variable PASSWD]
            subnet (str): [Subnet whose information is going to be displayed]
        """
        self._cmd.logger(
            ansi.style("SUBNET -> ", fg=ansi.fg.red)
            + ansi.style(subnet, fg=ansi.fg.blue)
        )
        scan_frame = pd.DataFrame(data=self.__scan_info[user][passwd][subnet])
        self._cmd.poutput(tabulate(scan_frame.T, headers="keys", tablefmt="psql"))

    def __show_scan_subnets(self) -> None:
        """[Shows the result of scanning all subnets of the
        current username and password]
        """
        user = self._cmd.USER
        passwd = self._cmd.PASSWD

        for subnet in self.__scan_info[user][passwd].keys():
            if len(self.__scan_info[user][passwd][subnet].keys()) != 0:
                self.__show_specific_subnet_info(user, passwd, subnet)
            else:
                self._cmd.error_logger.warning(
                    f"The scan on {subnet} has not collected any information "
                )

    def __show_scan_info(self) -> None:
        """[Function that will check if it is possible to display the scan
        info of a current username and password]
        """

        user = self._cmd.USER
        passwd = self._cmd.PASSWD

        self._cmd.info_logger.debug(
            f"Starting to show all the scan info of the different subnets using user: {user} passwd: {passwd}"
        )

        self.__show_user_passwd()
        if user in self.__scan_info.keys() and passwd in self.__scan_info[user].keys():
            self.__show_scan_subnets()
        else:
            self._cmd.error_logger.error(
                f"Current user and password not used yet user: {user} passwd: {passwd} "
            )

            self._cmd.do_help("scan")

    def __configure_scan_info(self) -> bool:
        """[Function that will configure the dictionary scan_info to do the scan]

        Returns:
            bool : [Returns the existence of a previous analysis of the
                        current subnet or if the user want to repeat the scan]
        """
        exists_subnet = False
        key = None

        user = self._cmd.USER
        passwd = self._cmd.PASSWD
        subnet = self._cmd.SUBNET

        if user not in self.__scan_info.keys():
            self.__scan_info[user] = {}
        if passwd not in self.__scan_info[user].keys():
            self.__scan_info[user][passwd] = {}
        if subnet in self.__scan_info[user][passwd].keys():

            self._cmd.error_logger.warning(
                f"The scan has already been passed with user: {user} passwd: {passwd} in {subnet}"
            )

            key = input("Do you want to repeat the scan ? Press 'y' but any other key:")
            exists_subnet = True
        return exists_subnet and key != ("y" or "Y")

    def __check_connectivity_of_scan(
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

        ip_with_color = ansi.style(ip, fg=ansi.fg.blue)
        conn_with_smb_dialect, smbclient = self.__try_scan_connection_with_smb1(ip)
        if not conn_with_smb_dialect:
            conn_without_smb_dialect, smbclient = self.__try_scan_connection_with_smb3(
                ip
            )

        if conn_with_smb_dialect or conn_without_smb_dialect:
            target_info = TargetInfo(ip_with_color, subnet, user_info)
            possibility_of_login = self.__check_scan_login_possibility(
                user_info, smbclient
            )

        return possibility_of_login, target_info, smbclient

    def __show_scan_results_asynchronous(self, target_info: TargetInfo) -> None:
        """[Display the results of an asynchronous scan]

        Args:
            target_info (TargetInfo): [Contains all the info to be displayed]
        """
        os_with_color = target_info.os
        ip_with_color = target_info.ip

        if target_info.psexec:
            admin = ansi.style("PsExec here!", fg=ansi.fg.yellow)
            if self._cmd.terminal_lock.acquire(blocking=False):
                self._cmd.async_alert(
                    LogSymbols.WARNING.value
                    + " "
                    + admin
                    + " "
                    + os_with_color
                    + " "
                    + ip_with_color
                )
                self._cmd.terminal_lock.release()
        elif self._cmd.terminal_lock.acquire(blocking=False):
            self._cmd.async_alert(
                LogSymbols.INFO.value + " " + os_with_color + " " + ip_with_color
            )
            self._cmd.terminal_lock.release()

    def __set_up_scan_results_asynchronous(
        self, smbclient: SMBConnection, target_info: TargetInfo
    ) -> None:
        """[Prepare everything to later show the saved information of the connection
                asynchronously]

        Args:
            smbclient (SMBConnection): [Object with the current smb connection]
            target_info (TargetInfo): [Object that contains info of the current target]
        """

        self.__configure_target_info_of_scan(target_info, smbclient)
        success_in_psexec = self.__check_psexec_possibility(smbclient)
        target_info.psexec = success_in_psexec
        self.__show_scan_results_asynchronous(target_info)
        self.__store_scan_results(target_info)

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
        ) = self.__check_connectivity_of_scan(user_info, subnet, ip)
        if possibility_of_login:
            self.__set_up_scan_results_asynchronous(smbclient, target_info)
        if smbclient is not None:
            smbclient.close()

    def __set_up_scan_actions_asynchronous(self) -> None:
        """[Prepare everything to scan asynchronously  using threads]"""
        user = self._cmd.USER
        password = self._cmd.PASSWD
        subnet = self._cmd.SUBNET
        user_info = UserInfo(user, password)

        self._cmd.info_logger.info("Starting to launch threads based on your cpu\n")

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
        self._cmd.info_logger.success(
            "Asynchronous scanning has been completed. Enabling scan command... "
        )
        self._cmd.enable_command("scan")

    def __asynchronous_way(self) -> None:
        """[Function that will start the asynchronous scan]"""
        self._cmd.info_logger.info(
            "Using asynchronous scan. The command will be disabled while its execution"
        )
        self._cmd.disable_command(
            "scan",
            ansi.style(
                "The scan command will be disabled while it is running",
                fg=ansi.fg.bright_yellow,
            ),
        )
        self._cmd.info_logger.info(
            ansi.style(
                "Starting... The messeges will be displayed as new computer is found",
                fg=ansi.fg.green,
            )
        )

        self._cmd.scan_thread = threading.Thread(
            target=self.__set_up_scan_actions_asynchronous
        )
        self._cmd.scan_thread.start()

    def __show_scan_results_synchronous(self, target_info: TargetInfo) -> None:
        """[Display the results of an synchronous scan]

        Args:
            target_info (TargetInfo): [Contains all the info to be displayed]
        """
        os_with_color = target_info.os
        ip_with_color = target_info.ip
        if target_info.psexec:
            admin = ansi.style("PsExec here!", fg=ansi.fg.yellow)
            self.__spinner.warn(admin + " " + os_with_color + " " + ip_with_color)
            # self._cmd.info("")
        else:
            self.__spinner.info(" " + os_with_color + " " + ip_with_color)

        self.__spinner.start()

    def __set_up_scan_results_synchronous(
        self, smbclient: SMBConnection, target_info: TargetInfo
    ) -> None:
        """[Prepare everything to later show the saved information of the connection
                synchronously]

        Args:
            smbclient (SMBConnection): [Object with the current smb connection]
            target_info (TargetInfo): [Object that contains info of the current target]
        """

        self.__configure_target_info_of_scan(target_info, smbclient)
        success_in_psexec_checker = self.__check_psexec_possibility(smbclient)
        target_info.psexec = success_in_psexec_checker
        # self.show_scan_results_synchronous(target_info)
        self.__store_scan_results(target_info)
        return target_info

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

        ip_with_color = ansi.style(str(ip), fg=ansi.fg.blue)
        self.__spinner.text = "Working in " + ip_with_color
        (
            possibility_of_login,
            target_info,
            smbclient,
        ) = self.__check_connectivity_of_scan(user_info, subnet, ip)
        if possibility_of_login:
            self.__set_up_scan_results_synchronous(smbclient, target_info)
        if smbclient is not None:
            smbclient.close()
        return target_info

    def __set_up_scan_actions_synchronous(self) -> None:
        """[Prepare everything to scan synchronously  using threads]"""

        user = self._cmd.USER
        password = self._cmd.PASSWD
        subnet = self._cmd.SUBNET
        user_info = UserInfo(user, password)

        self._cmd.info_logger.info("Starting to launch threads based on your cpu")
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
        number_of_spinner_possibilities = len(self.__spinner_list)
        number_of_spinner_selected = random.randrange(number_of_spinner_possibilities)

        self._cmd.info_logger.info("Using synchronous scan")
        self.__spinner = Halo(
            text="Loading...",
            spinner=self.__spinner_list[number_of_spinner_selected],
            stream=self._cmd.stdout,
        )
        self.__spinner.start()
        self.__set_up_scan_actions_synchronous()

    def __start_scan(self, args: argparse.Namespace) -> None:
        """[ Start scan of the subnet ]

        Args:
            args (argparse.Namespace): [ Arguments passed to the scan command ]
        """
        user = self._cmd.USER
        passwd = self._cmd.PASSWD
        subnet = self._cmd.SUBNET

        exists_subnet = self.__configure_scan_info()
        if not exists_subnet:
            self.__scan_info[user][passwd][subnet] = {}
            self.__show_user_passwd()
            if args.asynchronous:
                self.__asynchronous_way()
            else:
                self.__synchronous_way()

    argParser = cmd2.Cmd2ArgumentParser(
        description="""Tool to know if there is a possibility to perform psexec. 
        Without arguments this tool will scan the Subnet"""
    )
    argParser.add_argument(
        "-SI",
        "--show_info",
        action="store_true",
        help="""It shows the information of all the subnets of the current user 
            and password specified in the settable variables(USER, PASSWD)""",
    )
    argParser.add_argument(
        "-A",
        "--asynchronous",
        action="store_true",
        help="""Run the command asynchronous. To use this functionality, 
        the application must be running in a terminal that supports VT100 
        control characters and readline""",
    )
    argParser.add_argument(
        "-SS",
        "--show_settable",
        action="store_true",
        help="Show Settable variables for this command",
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

        if args.show_info:
            self.__show_scan_info()
        elif args.show_settable:
            self._cmd.show_settable_variables_necessary(settable_variables_required)
        elif self._cmd.check_settable_variables_value(settable_variables_required):
            self.__start_scan(args)
