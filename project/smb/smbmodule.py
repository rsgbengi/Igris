#!/usr/bin/env python
# -*- coding: utf-8 -*-


import argparse
import concurrent.futures
import functools
from ipaddress import IPv4Address, IPv4Network
import ntpath
import random
import shlex

from halo import Halo
import threading
from typing import Tuple
import cmd2
import pandas as pd
from cmd2 import CommandSet, ansi, with_default_category
from impacket.smb import SMB_DIALECT
from impacket.smbconnection import SMBConnection
from log_symbols import LogSymbols
from pypsexec.client import Client
from pypsexec.exceptions import PAExecException, SCMRException
from smbprotocol.exceptions import CannotDelete
from spinners.spinners import Spinners
from tabulate import tabulate

from .gatherinfo.scaninfo import TargetInfo, UserInfo
from .gatherinfo.psexecinfo import PsexecShellVariables


@with_default_category("SMB Recon")
class SMBCommandSet(CommandSet):
    def __init__(self):
        super().__init__()
        self.scan_info = {}
        self.spinner_list = [key.name for key in Spinners]
        self.spinner = None

    def try_scan_connection_with_smb1(
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

            self._cmd.logger.info(f"Connection success using smb1 at {ip}")
            succeed_in_connection = True
        except Exception:  # SessionError not working as expected
            self._cmd.logger.debug(f"Connection refused using smb1 at {ip}")

        return succeed_in_connection, smbclient

    def try_scan_connection_with_smb3(
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
            self._cmd.logger.info(f"Connection success using smb3 at {ip}")
        except Exception:
            self._cmd.logger.debug(f"Connection refused using smb3 at {ip}")

        return succeed_in_connection, smbclient

    def check_scan_login_possibility(
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
            self._cmd.logger.info(f"Login successful at {ip}")
        except Exception:
            self._cmd.logger.debug(f"Login rejected at {ip}")
        return succeed_in_login

    def store_scan_results(self, target_info: TargetInfo) -> None:
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

        self._cmd.logger.info(f"Saving scan information")

        self.scan_info[user][passwd][subnet][ip_with_color] = {
            ansi.style("Server Name", fg=ansi.fg.red): target_info.computer_name,
            ansi.style("Operating System", fg=ansi.fg.red): target_info.os,
            ansi.style("Signed", fg=ansi.fg.red): target_info.signed,
        }

        if psexec_possibility:
            admin = ansi.style("PsExec here!", fg=ansi.fg.yellow)
            self.scan_info[user][passwd][subnet][ip_with_color][
                ansi.style("PsExec", fg=ansi.fg.red)
            ] = admin

    def configure_target_info_of_scan(
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
        self._cmd.logger.info(
            f"Loading target info of {smbclient.getServerName()} at {ip}"
        )
        target_info.signed = smbclient.isSigningRequired()
        target_info.computer_name = smbclient.getServerName()
        target_info.os = smbclient.getServerOS()

    def check_psexec_possibility(self, smbclient: SMBConnection) -> bool:
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
            self._cmd.logger.info(
                f"Possibility of psexec on {smbclient.getServerName()} at {ip}"
            )
        except Exception:
            self._cmd.logger.info(
                f"Error of psexec on {smbclient.getServerName()} at {ip}"
            )

        return success_in_psexec

    def show_user_passwd(self) -> None:
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

    def show_specific_subnet_info(self, user: str, passwd: str, subnet: str) -> None:
        """[Shows the information of a specific subnet]

        Args:
            user (str): [Current value of the settable variable USER]
            passwd (str): [Current value of the settable variable PASSWD]
            subnet (str): [Subnet whose information is going to be displayed]
        """
        self._cmd.poutput(
            ansi.style("SUBNET -> ", fg=ansi.fg.red)
            + ansi.style(subnet, fg=ansi.fg.blue)
        )
        scan_frame = pd.DataFrame(data=self.scan_info[user][passwd][subnet])
        self._cmd.poutput(tabulate(scan_frame.T, headers="keys", tablefmt="psql"))

    def show_scan_subnets(self) -> None:
        """[Shows the result of scanning all subnets of the
        current username and password]
        """
        user = self._cmd.USER
        passwd = self._cmd.PASSWD

        for subnet in self.scan_info[user][passwd].keys():
            if len(self.scan_info[user][passwd][subnet].keys()) != 0:
                self.show_specific_subnet_info(user, passwd, subnet)
            else:
                self._cmd.pwarning(
                    f"The scan on {subnet} has not collected any information "
                )

    def show_scan_info(self) -> None:
        """[Function that will check if it is possible to display the scan
        info of a current username and password]
        """

        user = self._cmd.USER
        passwd = self._cmd.PASSWD

        self._cmd.logger.info(
            f"Starting to show all the scan info of the different subnets using user: {user} passwd: {passwd}"
        )

        self.show_user_passwd()
        if user in self.scan_info.keys() and passwd in self.scan_info[user].keys():
            self.show_scan_subnets()
        else:
            self._cmd.logger.error(
                f"Current user and password not used yet user: {user} passwd: {passwd} "
            )
            self._cmd.perror("There is no scan information for this user or password")
            self._cmd.do_help("scan")

    def configure_scan_info(self) -> bool:
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

        if user not in self.scan_info.keys():
            self.scan_info[user] = {}
        if passwd not in self.scan_info[user].keys():
            self.scan_info[user][passwd] = {}
        if subnet in self.scan_info[user][passwd].keys():
            self._cmd.pwarning(
                "The scan has already been passed with this user and subnet. Use -SI to see the results."
            )
            key = input(
                "Do you want to repeat the scan ? Press 'y' but any other key: "
            )
            self._cmd.logger.warning(
                f"The scan has already been passed with user: {user} passwd: {passwd} in {subnet}"
            )
            exists_subnet = True
        return exists_subnet and key != ("y" or "Y")

    def check_connectivity_of_scan(
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
        conn_with_smb_dialect, smbclient = self.try_scan_connection_with_smb1(ip)
        if not conn_with_smb_dialect:
            conn_without_smb_dialect, smbclient = self.try_scan_connection_with_smb3(ip)

        if conn_with_smb_dialect or conn_without_smb_dialect:
            target_info = TargetInfo(ip_with_color, subnet, user_info)
            possibility_of_login = self.check_scan_login_possibility(
                user_info, smbclient
            )

        return possibility_of_login, target_info, smbclient

    def show_scan_results_asynchronous(self, target_info: TargetInfo) -> None:
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

    def set_up_scan_results_asynchronous(
        self, smbclient: SMBConnection, target_info: TargetInfo
    ) -> None:
        """[Prepare everything to later show the saved information of the connection
                asynchronously]

        Args:
            smbclient (SMBConnection): [Object with the current smb connection]
            target_info (TargetInfo): [Object that contains info of the current target]
        """

        self.configure_target_info_of_scan(target_info, smbclient)
        success_in_psexec = self.check_psexec_possibility(smbclient)
        target_info.psexec = success_in_psexec
        self.show_scan_results_asynchronous(target_info)
        self.store_scan_results(target_info)

    def is_user_in_admin_group_asynchronous(
        self, user_info: UserInfo, subnet: str, ip: IPv4Address
    ) -> None:
        """[Function that is used to know if the user is an administrator and
                is currently able to psexec(asynchronous way)]

        Args:
            user_info (UserInfo): [User info needed to know user privileges]
            subnet (str): [Target subnet to scan]
            ip (IPv4Address): [Ip target of the current remote host]
        """
        possibility_of_login, target_info, smbclient = self.check_connectivity_of_scan(
            user_info, subnet, ip
        )
        if possibility_of_login:
            self.set_up_scan_results_asynchronous(smbclient, target_info)
        if smbclient is not None:
            smbclient.close()

    def set_up_scan_actions_asynchronous(self) -> None:
        """[Prepare everything to scan asynchronously  using threads]"""
        user = self._cmd.USER
        password = self._cmd.PASSWD
        subnet = self._cmd.SUBNET
        user_info = UserInfo(user, password)

        self._cmd.logger.info("Starting to launch threads based on your cpu")

        with concurrent.futures.ThreadPoolExecutor() as executor:
            executor.map(
                functools.partial(
                    self.is_user_in_admin_group_asynchronous, user_info, subnet
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
        self._cmd.logger.success(
            "Asynchronous scanning has been completed. Enabling scan command... "
        )
        self._cmd.enable_command("scan")

    def asynchronous_way(self) -> None:
        """[Function that will start the asynchronous scan]"""
        self._cmd.logger.info(
            "Using asynchronous scan. The command will be disabled while its execution"
        )
        self._cmd.disable_command(
            "scan",
            ansi.style(
                "The scan command will be disabled while it is running",
                fg=ansi.fg.bright_yellow,
            ),
        )
        self._cmd.poutput(
            ansi.style(
                "Starting... The messeges will be displayed as new computer is found",
                fg=ansi.fg.green,
            )
        )

        self._cmd.scan_thread = threading.Thread(
            target=self.set_up_scan_actions_asynchronous
        )
        self._cmd.scan_thread.start()

    def show_scan_results_synchronous(self, target_info: TargetInfo) -> None:
        """[Display the results of an synchronous scan]

        Args:
            target_info (TargetInfo): [Contains all the info to be displayed]
        """
        os_with_color = target_info.os
        ip_with_color = target_info.ip
        if target_info.psexec:
            admin = ansi.style("PsExec here!", fg=ansi.fg.yellow)
            self.spinner.warn(admin + " " + os_with_color + " " + ip_with_color)
        else:
            self.spinner.info(" " + os_with_color + " " + ip_with_color)

        self.spinner.start()

    def set_up_scan_results_synchronous(
        self, smbclient: SMBConnection, target_info: TargetInfo
    ) -> None:
        """[Prepare everything to later show the saved information of the connection
                synchronously]

        Args:
            smbclient (SMBConnection): [Object with the current smb connection]
            target_info (TargetInfo): [Object that contains info of the current target]
        """

        self.configure_target_info_of_scan(target_info, smbclient)
        success_in_psexec_checker = self.check_psexec_possibility(smbclient)
        target_info.psexec = success_in_psexec_checker
        # self.show_scan_results_synchronous(target_info)
        self.store_scan_results(target_info)
        return target_info

    def is_user_in_admin_group_synchronous(
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
        self.spinner.text = "Working in " + ip_with_color
        possibility_of_login, target_info, smbclient = self.check_connectivity_of_scan(
            user_info, subnet, ip
        )
        if possibility_of_login:
            self.set_up_scan_results_synchronous(smbclient, target_info)
        if smbclient is not None:
            smbclient.close()
        return target_info

    def set_up_scan_actions_synchronous(self) -> None:
        """[Prepare everything to scan synchronously  using threads]"""

        user = self._cmd.USER
        password = self._cmd.PASSWD
        subnet = self._cmd.SUBNET
        user_info = UserInfo(user, password)

        self._cmd.logger.info("Starting to launch threads based on your cpu")
        with concurrent.futures.ThreadPoolExecutor() as executor:
            try:
                results = executor.map(
                    functools.partial(
                        self.is_user_in_admin_group_synchronous, user_info, subnet
                    ),
                    IPv4Network(subnet),
                )
                for target_info in results:
                    if (
                        (target_info is not None)
                        and (target_info.os is not None)
                        and (target_info.ip is not None)
                    ):
                        self.show_scan_results_synchronous(target_info)
            except KeyboardInterrupt:
                executor.shutdown()
                self._cmd.pwarning("\n Exiting ...")
                self._cmd.logger.exception("The scan was interrupted")
        self.spinner.succeed("The scan has finished")
        self._cmd.logger.success("Synchronous scanning has been completed")

    def synchronous_way(self) -> None:
        """[ Function that will start the synchronous scan]"""
        number_of_spinner_possibilities = len(self.spinner_list)
        number_of_spinner_selected = random.randrange(number_of_spinner_possibilities)

        self._cmd.logger.info("Using synchronous scan")
        self.spinner = Halo(
            text="Loading...",
            spinner=self.spinner_list[number_of_spinner_selected],
            stream=self._cmd.stdout,
        )
        self.spinner.start()
        self.set_up_scan_actions_synchronous()

    def start_scan(self, args: argparse.Namespace) -> None:
        """[ Start scan of the subnet ]

        Args:
            args (argparse.Namespace): [ Arguments passed to the scan command ]
        """
        user = self._cmd.USER
        passwd = self._cmd.PASSWD
        subnet = self._cmd.SUBNET

        exists_subnet = self.configure_scan_info()
        if not exists_subnet:
            self.scan_info[user][passwd][subnet] = {}
            self.show_user_passwd()
            if args.asynchronous:
                self.asynchronous_way()
            else:
                self.synchronous_way()

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

        self._cmd.logger.info(
            f"Starting scan command using user: {user} passwd: {passwd} subnet: {subnet}"
        )

        settable_variables_required = {
            "SUBNET": subnet,
            "USER": user,
            "PASSWD": passwd,
        }

        if args.show_info:
            self.show_scan_info()
        elif args.show_settable:
            self._cmd.show_settable_variables_necessary(settable_variables_required)
        elif self._cmd.check_settable_variables_value(settable_variables_required):
            self.start_scan(args)

    def cd_case_previous_directory(
        self, psexec_info: PsexecShellVariables, separate_dir: list[str]
    ) -> None:
        """[Function to prepare everithing for 'cd ..']

        Args:
            psexec_info (PsexecShellVariables): [ Object that containing information of the current session psexec ]
            separate_dir (str): [ Current directory in a list ]
        """

        actual_work_dir = psexec_info.actual_work_dir
        separate_dir = actual_work_dir.split("\\")
        n = len(separate_dir)
        if n == 2:
            psexec_info.possible_work_dir = separate_dir[0] + "\\"
        else:
            separator = "\\"
            psexec_info.possible_work_dir = separator.join(separate_dir[: n - 1])

    def exec_shell_command(self, psexec_info: PsexecShellVariables) -> None:
        """[Function to run a command within the cmd.exe or powershell.exe context]

        Args:
            psexec_info (PsexecShellVariables): [ Object that containing information of the current session psexec ]
        """
        conn = psexec_info.conn
        shell_command = psexec_info.shell_command
        actual_work_dir = psexec_info.actual_work_dir
        executable = psexec_info.executable
        try:
            result = conn.run_executable(
                executable,
                arguments="/c " + shell_command,
                working_dir=actual_work_dir,
            )

            if result[0].decode("utf-8"):
                self._cmd.poutput(result[0].decode("utf-8"))
            if result[1].decode("utf-8"):
                self._cmd.perror(result[1].decode("utf-8"))
        except KeyboardInterrupt:
            self._cmd.pwarning("Stopped current command")
            self._cmd.logger.warning(f"The command {shell_command} has been stopped")

    def exec_particular_command(self, conn: Client, args: argparse.Namespace) -> None:
        """[ Function to run a command like 'whoami.exe' outside of cmd.exe or powershell.exe ]

        Args:
            conn (Client): [ Object to run the command on the remote machine ]
            args (argparse.Namespace): [Arguments passed to the psexec command]
        """
        try:
            result = conn.run_executable(args.command, arguments=args.arguments)
            if result[0].decode("utf-8"):
                self._cmd.poutput(result[0].decode("utf-8"))
            if result[1].decode("utf-8"):
                self._cmd.perror(result[1].decode("utf-8"))
        except PAExecException:
            self._cmd.perror("The program execution has failed")
            self._cmd.logger.error(f"The command {args.command} has failed")
        except KeyboardInterrupt:
            self._cmd.pwarning("Exiting ...")
            self._cmd.logger.warning(f"The command {args.command} has been stopped")
        finally:
            self.close_connection(conn)

    def select_command_line(self, psexec_info: PsexecShellVariables) -> str:
        """[Function to generate command line]

        Args:
            psexec_info (PsexecShellVariables): [Object that containing information of the current session psexec]

        Returns:
            str: [Returns the command line based on whether cmd.exe or powershell.exe]
        """
        executable = psexec_info.executable
        actual_work_dir = psexec_info.actual_work_dir
        if executable == "cmd.exe":
            return ansi.style("CMD->" + actual_work_dir + " >", fg=ansi.fg.green)
        else:
            return ansi.style("PS->" + actual_work_dir + " >", fg=ansi.fg.yellow)

    def set_up_directory(self, psexec_info: PsexecShellVariables) -> bool:
        """[ Function to set the new directory ]

        Args:
            psexec_info (PsexecShellVariables): [ Object that containing information of the current session psexec ]

        Returns:
            bool: [ Returns if the cd command has been used]
        """

        separate_command = shlex.split(psexec_info.shell_command)
        cd_used = False
        actual_work_dir = psexec_info.actual_work_dir
        if (
            "cd" in separate_command
            and len(separate_command) == 2
            and "." not in separate_command
        ):
            cd_used = True
            separate_dir = separate_command[1]
            if separate_dir == "..":
                self.cd_case_previous_directory(psexec_info, separate_dir)
            elif actual_work_dir == "C:\\":
                psexec_info.possible_work_dir = actual_work_dir + separate_dir
            else:
                psexec_info.possible_work_dir = actual_work_dir + "\\" + separate_dir

        return cd_used

    def change_directory(self, psexec_info: PsexecShellVariables) -> bool:
        """[ Function that performs directory change ]

        Args:
            psexec_info (PsexecShellVariables): [Object that containing information of the current session psexec]

        Returns:
            bool: [Returns if the directory  change was successful ]
        """
        success_changing_directory = True
        conn = psexec_info.conn
        possible_work_dir = psexec_info.possible_work_dir
        executable = psexec_info.executable
        try:
            conn.run_executable(
                executable, arguments="/c cd", working_dir=possible_work_dir
            )
        except PAExecException:
            self._cmd.perror("Directory not found")
            success_changing_directory = False
        except KeyboardInterrupt:
            self._cmd.pwarning("Cd has been stopped")
            success_changing_directory = False

        return success_changing_directory

    def manage_actual_directory(
        self, psexec_info: PsexecShellVariables, success_changing_directory: bool
    ) -> None:
        """[ Set the attributes  of psexec_info to change directory based on the success
                of the 'change_directory' function]
        Args:
            psexec_info (PsexecShellVariables): [Object that containing information of the current session psexec]
            success_changing_directory (bool): [ Argument to know if the directory change has been made successfully]
        """
        possible_directory = psexec_info.possible_work_dir
        actual_work_dir = psexec_info.actual_work_dir

        if success_changing_directory:
            psexec_info.actual_work_dir = possible_directory
        else:
            psexec_info.possible_work_dir = actual_work_dir

    def directory_operations(self, psexec_info: PsexecShellVariables) -> bool:
        """[ Procedure to make a directory change ]

        Args:
            psexec_info (PsexecShellVariables): [ Object that contains everything necessary to perform commands ]

        Returns:
            bool: [ Returns if cd has been used ]
        """
        cd_used = self.set_up_directory(psexec_info)
        if cd_used:
            success_changing_directory = self.change_directory(psexec_info)
            self.manage_actual_directory(psexec_info, success_changing_directory)
        return cd_used

    def close_connection(self, conn: Client) -> None:
        """[ Function to close psexec connection ]

        Args:
            conn (Client) : [ Object containing the connection ]
        """
        try:
            conn.remove_service()
            conn.disconnect()
        except CannotDelete:
            self._cmd.perror(
                """The current psexec session has been stopped. You will have to restart Igris to continue.
                    After that you will have to use 'psexec -CL' to clean paexec files """
            )
            self._cmd.logger.error(
                "The current psexec session has been stopped. You will have to restart Igris to continue."
            )

    def set_up_executing_in_shell(self, psexec_info: PsexecShellVariables) -> None:
        """[Configure everything based on the comand entered by the user]

        Args:
            psexec_info (PsexecShellVariables): [ Object that contains everything necessary to perform commands ]
        """
        cd_used = self.directory_operations(psexec_info)
        if not cd_used:
            self.exec_shell_command(psexec_info)

    def shell(self, psexec_info: PsexecShellVariables) -> None:
        """[Function to perform interactively cmd.exe or powershell.exe]

        Args:
            psexec_info (PsexecShellVariables): [Object that contains everything necessary to perform commands]
        """
        shell_command = ""
        conn = psexec_info.conn

        self._cmd.logger.info(f"Starting {psexec_info.executable} interactively")
        self.spinner.info("Putting 'exit' or using 'ctrl+c' to exit the shell")
        try:
            while shell_command != "exit":
                line = self.select_command_line(psexec_info)
                shell_command = input(line)
                psexec_info.shell_command = shell_command
                if shell_command.strip() != "exit":
                    self.set_up_executing_in_shell(psexec_info)
        except KeyboardInterrupt:
            print()
        finally:
            self._cmd.logger.info(f"Exiting {psexec_info.executable}")
            self.close_connection(conn)

    def try_psexec_connection(self, conn: Client) -> bool:
        """[Function to try to connect to the target machine to perform psexec]

        Args:
            conn (Client): [Object to established the connection]

        Returns:
            bool : [Returns if the connection has been established]
        """
        connection_result = False
        try:
            conn.connect()
            connection_result = True
            self._cmd.logger.info("The connection has been established successfully")
        except ValueError:
            self._cmd.logger.exception("Error when creating the connection")
            self._cmd.perror(
                "Error when creating the connection. Use the scan command to find out if your user has the ability to psexec.."
            )
        return connection_result

    def try_create_service_of_psexec(self, conn: Client) -> bool:
        """[Function to create the service to perform psexec]

        Args:
            conn (Client): [ Object to create the service on the remote machine ]

        Returns:
            bool : [Returns if the service has been created]
        """
        success_creating_service = False
        try:
            conn.create_service()
            success_creating_service = True
            self._cmd.logger.info("The servide has been created successfully")
            self.spinner.succeed("The service has been created")
        except Exception:
            self._cmd.logger.exception("Error when creating the service")
            self._cmd.perror("Error when creating the service")
            self.spinner.stop()
        return success_creating_service

    def try_to_execute_command(self, psexec_info):
        conn = psexec_info.conn
        try:
            self.exec_shell_command(psexec_info)
        except PAExecException:
            self._cmd.perror("The command could not be executed")
        finally:
            self.close_connection(conn)

    def cmd_powershell_commands(
        self, args: argparse.Namespace, psexec_info: PsexecShellVariables
    ) -> None:
        """[Function to launch commands using cmd.exe or powershell.exe]

        Args:
            args (argparser.Namespace): [ Arguments passed to the do_psexec command]
            psexec_info (PsexecShellVariables): [ Info of the current connection ]
        """
        if args.interactive:
            self.shell(psexec_info)
        elif args.arguments:
            psexec_info.shell_command = args.arguments
            self.try_to_execute_command(psexec_info)
        else:
            self._cmd.perror(
                "To run cmd.exe or powershell.exe you need to pass an argument or indicate interactive mode using -I"
            )

    def prepare_service(self, conn: Client) -> bool:
        """[Set up the psexec service on the remote machine]

        Args:
            conn (Client): [ Object with the connection to the remote machine ]

        Returns:
            bool: [ Returns if the service has been created successfully ]
        """

        number_of_spinner_possibilities = len(self.spinner_list)
        number_of_spinner_selected = random.randrange(number_of_spinner_possibilities)

        self.spinner = Halo(
            text="Loading the service...",
            spinner=self.spinner_list[number_of_spinner_selected],
            stream=self._cmd.stdout,
        )
        self.spinner.start()
        return self.try_create_service_of_psexec(conn)

    def psexec_execution_options(self, args: argparse.Namespace, conn: Client) -> None:
        """[ Function that checks what type of command the user is going to perform ]

        Args:
            args (argparse.Namespace): [ Arguments passed to the psexec command ]
            conn (Client): [ Object with the client options to execute commands on the remote machine ]
        """

        psexec_info = PsexecShellVariables(conn, args.command)
        if "cmd" in args.command or "powershell" in args.command:
            self.cmd_powershell_commands(args, psexec_info)
        elif args.interactive:
            self._cmd.perror("Interactive only is valid with cmd.exe or powershell.exe")
        else:
            self.exec_particular_command(conn, args)

    def process_to_perform_psexec(self, args: argparse.Namespace) -> None:
        """[Function that connect, create the service and execute commands on the remote machine ]

        Args:
            args (argparse.Namespace): [ Arguments passed to the psexec command ]
        """
        ip_target = self._cmd.IP_TARGET
        user = self._cmd.USER
        passwd = self._cmd.PASSWD

        conn = Client(
            ip_target,
            user,
            passwd,
            encrypt=args.encryption,
        )
        success_in_connection = self.try_psexec_connection(conn)
        if success_in_connection:
            success_creating_service = self.prepare_service(conn)
            if success_creating_service:
                self.psexec_execution_options(args, conn)

    def clean_paexec_files(self, args):
        ip_target = self._cmd.IP_TARGET
        user = self._cmd.USER
        passwd = self._cmd.PASSWD

        conn = Client(
            ip_target,
            user,
            passwd,
            encrypt=args.encryption,
        )
        self.try_psexec_connection(conn)
        try:
            conn.cleanup()
            conn.disconnect()
            self._cmd.poutput("Successful Cleaning")
            self._cmd.logger.info(
                f"Successful cleaning at {ip_target} with user {user} and passwd {passwd}"
            )
        except SCMRException:
            self._cmd.perror("Cannot delete files. Please restart Igris")
            self._cmd.logger.error(
                f"Cannot delete files in {ip_target}. Please restart Igris"
            )

    argParser = cmd2.Cmd2ArgumentParser(description="Tool to execute commands remotely")
    argParser.add_argument(
        "-C", "--command", help="Run a command on the windows machine."
    )
    argParser.add_argument(
        "-I",
        "--interactive",
        action="store_true",
        help="For an interactive cmd.exe or powershell.exe",
    )
    argParser.add_argument(
        "-ARG",
        "--arguments",
        help="""Arguments for a selected command. If there is more than one, 
        quotes must be used""",
    )
    argParser.add_argument(
        "-E",
        "--encryption",
        action="store_true",
        help="""Argument to encrypt the communication. Encryption does not 
        work with windows 7 and server 2008""",
    )
    argParser.add_argument(
        "-SS",
        "--show_settable",
        action="store_true",
        help="Show Settable variables for this command",
    )
    argParser.add_argument(
        "-CL",
        "--clean_remote_files",
        action="store_true",
        help="Command to clean PaExec files on failure",
    )

    @cmd2.with_argparser(argParser)
    def do_psexec(self, args: argparse.Namespace) -> None:
        """[Psexec is a command that allows remote execution on a windows machines]

        Args:
            args (argparse.Namespace): [Arguments passed to the  psexec command]
        """

        ip_target = self._cmd.IP_TARGET
        user = self._cmd.USER
        passwd = self._cmd.PASSWD

        settable_variables_required = {
            "IP_TARGET": ip_target,
            "USER": user,
            "PASSWD": passwd,
        }
        self._cmd.logger.info(
            f"Starting psexec with the user {user} and the password {passwd} in {ip_target}"
        )

        if args.show_settable:
            self._cmd.show_settable_variables_necessary(settable_variables_required)
            return
        if not self._cmd.check_settable_variables_value(settable_variables_required):
            return
        if args.clean_remote_files:
            self.clean_paexec_files(args)
            return

        self.process_to_perform_psexec(args)
