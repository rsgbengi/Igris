#!/usr/bin/env python
# -*- coding: utf-8 -*-


import argparse
import random
import shlex

from halo import Halo
import cmd2
from cmd2 import CommandSet, ansi, with_default_category
from pypsexec.client import Client
from pypsexec.exceptions import PAExecException, SCMRException
from smbprotocol.exceptions import CannotDelete
from spinners.spinners import Spinners

from .gatherinfo import PsexecShellVariables


@with_default_category("SMB Recon")
class Psexec(CommandSet):
    def __init__(self):
        super().__init__()
        self.scan_info = {}
        self.spinner_list = [key.name for key in Spinners]
        self.spinner = None

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
