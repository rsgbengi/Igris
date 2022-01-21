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
from smbprotocol.exceptions import LogonFailure
from smbprotocol.exceptions import CannotDelete
from spinners.spinners import Spinners

from .gatherinfo import PsexecShellVariables

@with_default_category("Utilities")
class Psexec(CommandSet):
    def __init__(self):
        super().__init__()
        self.__spinner_list = [key.name for key in Spinners]
        self.__spinner = None

    def __cd_case_previous_directory(
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

    def __exec_shell_command(self, psexec_info: PsexecShellVariables) -> None:
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
                self._cmd.info_logger.info(result[0].decode("utf-8"))
            if result[1].decode("utf-8"):
                self._cmd.error_logger.error(result[1].decode("utf-8"))
        except KeyboardInterrupt:
            self._cmd.error_logger.warning("Stopped current command")
            self._cmd.error_logger.warning(
                f"The command {shell_command} has been stopped"
            )

    def __exec_particular_command(self, conn: Client, args: argparse.Namespace) -> None:
        """[ Function to run a command like 'whoami.exe' outside of cmd.exe or powershell.exe ]

        Args:
            conn (Client): [ Object to run the command on the remote machine ]
            args (argparse.Namespace): [Arguments passed to the psexec command]
        """
        try:
            result = conn.run_executable(args.command, arguments=args.arguments)
            if result[0].decode("utf-8"):
                self._cmd.info_logger.info(result[0].decode("utf-8"))
            if result[1].decode("utf-8"):
                self._cmd.error_logger.error(result[1].decode("utf-8"))
        except PAExecException:
            self._cmd.error_logger.error("The program execution has failed")
            self._cmd.error_logger.error(f"The command {args.command} has failed")
        except KeyboardInterrupt:
            self._cmd.error_logger.warning("Exiting ...")
            self._cmd.error_logger.warning(
                f"The command {args.command} has been stopped"
            )
        finally:
            self.__close_connection(conn)

    def __select_command_line(self, psexec_info: PsexecShellVariables) -> str:
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

    def __set_up_directory(self, psexec_info: PsexecShellVariables) -> bool:
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
                self.__cd_case_previous_directory(psexec_info, separate_dir)
            elif actual_work_dir == "C:\\":
                psexec_info.possible_work_dir = actual_work_dir + separate_dir
            else:
                psexec_info.possible_work_dir = actual_work_dir + "\\" + separate_dir

        return cd_used

    def __change_directory(self, psexec_info: PsexecShellVariables) -> bool:
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
            self._cmd.error_logger.error("Directory not found")
            success_changing_directory = False
        except KeyboardInterrupt:
            self._cmd.error_logger.warning("Cd has been stopped")
            success_changing_directory = False

        return success_changing_directory

    def __manage_actual_directory(
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

    def __directory_operations(self, psexec_info: PsexecShellVariables) -> bool:
        """[ Procedure to make a directory change ]

        Args:
            psexec_info (PsexecShellVariables): [ Object that contains everything necessary to perform commands ]

        Returns:
            bool: [ Returns if cd has been used ]
        """
        cd_used = self.__set_up_directory(psexec_info)
        if cd_used:
            success_changing_directory = self.__change_directory(psexec_info)
            self.__manage_actual_directory(psexec_info, success_changing_directory)
        return cd_used

    def __close_connection(self, conn: Client) -> None:
        """[ Function to close psexec connection ]

        Args:
            conn (Client) : [ Object containing the connection ]
        """
        try:
            conn.remove_service()
            conn.disconnect()
        except CannotDelete:
            self._cmd.error_logger.error(
                """The current psexec session has been stopped. You will have to restart Igris to continue.
                    After that you will have to use 'psexec -CL' to clean paexec files """
            )

    def __set_up_executing_in_shell(self, psexec_info: PsexecShellVariables) -> None:
        """[Configure everything based on the comand entered by the user]

        Args:
            psexec_info (PsexecShellVariables): [ Object that contains everything necessary to perform commands ]
        """
        cd_used = self.__directory_operations(psexec_info)
        if not cd_used:
            self.__exec_shell_command(psexec_info)

    def __shell(self, psexec_info: PsexecShellVariables) -> None:
        """[Function to perform interactively cmd.exe or powershell.exe]

        Args:
            psexec_info (PsexecShellVariables): [Object that contains everything necessary to perform commands]
        """
        shell_command = ""
        conn = psexec_info.conn

        self._cmd.info_logger.info(f"Starting {psexec_info.executable} interactively")
        self.__spinner.info("Putting 'exit' or using 'ctrl+c' to exit the shell")
        try:
            while shell_command != "exit":
                line = self.__select_command_line(psexec_info)
                shell_command = input(line)
                psexec_info.shell_command = shell_command
                if shell_command.strip() != "exit":
                    self.__set_up_executing_in_shell(psexec_info)
        except KeyboardInterrupt:
            print()
        finally:
            self._cmd.info_logger.info(f"Exiting {psexec_info.executable}")
            self.__close_connection(conn)

    def __try_psexec_connection(self, conn: Client) -> bool:
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
            self._cmd.info_logger.info(
                "The connection has been established successfully"
            )
        except (ValueError, LogonFailure):
            self._cmd.error_logger.error(
                "Error when creating the connection. Use the scan command to find out if your user has the ability to psexec."
            )
        return connection_result

    def __try_create_service_of_psexec(self, conn: Client) -> bool:
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
            self._cmd.info_logger.debug("The servide has been created successfully")
            self.__spinner.succeed("The service has been created")
        except Exception:
            self._cmd.error_logger.error("Error when creating the service")
            self.__spinner.stop()
        return success_creating_service

    def __try_to_execute_command(self, psexec_info):
        conn = psexec_info.conn
        try:
            self.__exec_shell_command(psexec_info)
        except PAExecException:
            self._cmd.error_logger.error("The command could not be executed")
        finally:
            self.__close_connection(conn)

    def __cmd_powershell_commands(
        self, args: argparse.Namespace, psexec_info: PsexecShellVariables
    ) -> None:
        """[Function to launch commands using cmd.exe or powershell.exe]

        Args:
            args (argparser.Namespace): [ Arguments passed to the do_psexec command]
            psexec_info (PsexecShellVariables): [ Info of the current connection ]
        """
        if args.interactive:
            self.__shell(psexec_info)
        elif args.arguments:
            psexec_info.shell_command = args.arguments
            self.__try_to_execute_command(psexec_info)
        else:
            self._cmd.error_logger.error(
                "To run cmd.exe or powershell.exe you need to pass an argument or indicate interactive mode using -I"
            )

    def __prepare_service(self, conn: Client) -> bool:
        """[Set up the psexec service on the remote machine]

        Args:
            conn (Client): [ Object with the connection to the remote machine ]

        Returns:
            bool: [ Returns if the service has been created successfully ]
        """

        number_of_spinner_possibilities = len(self.__spinner_list)
        number_of_spinner_selected = random.randrange(number_of_spinner_possibilities)

        self.__spinner = Halo(
            text="Loading the service...",
            spinner=self.__spinner_list[number_of_spinner_selected],
            stream=self._cmd.stdout,
        )
        self.__spinner.start()
        return self.__try_create_service_of_psexec(conn)

    def __psexec_execution_options(
        self, args: argparse.Namespace, conn: Client
    ) -> None:
        """[ Function that checks what type of command the user is going to perform ]

        Args:
            args (argparse.Namespace): [ Arguments passed to the psexec command ]
            conn (Client): [ Object with the client options to execute commands on the remote machine ]
        """

        psexec_info = PsexecShellVariables(conn, args.command)
        if "cmd" in args.command or "powershell" in args.command:
            self.__cmd_powershell_commands(args, psexec_info)
        elif args.interactive:
            self._cmd.error_logger.error(
                "Interactive only is valid with cmd.exe or powershell.exe"
            )
        else:
            self.__exec_particular_command(conn, args)

    def __process_to_perform_psexec(self, args: argparse.Namespace) -> None:
        """[Function that connect, create the service and execute commands on the remote machine ]

        Args:
            args (argparse.Namespace): [ Arguments passed to the psexec command ]
        """
        rhost = self._cmd.RHOST
        user = self._cmd.USER
        passwd = self._cmd.PASSWD

        conn = Client(
            rhost,
            user,
            passwd,
            encrypt=args.encryption,
        )
        success_in_connection = self.__try_psexec_connection(conn)
        if success_in_connection:
            success_creating_service = self.__prepare_service(conn)
            if success_creating_service:
                self.__psexec_execution_options(args, conn)

    def __clean_paexec_files(self, args: argparse.Namespace) -> None:
        """[Function to clean files from the remote host]

        Args:
            args (argparse.Namespace): [ Arguments passed to the psexec command ]
        """

        rhost = self._cmd.RHOST
        user = self._cmd.USER
        passwd = self._cmd.PASSWD

        conn = Client(
            rhost,
            user,
            passwd,
            encrypt=args.encryption,
        )
        self.__try_psexec_connection(conn)
        try:
            conn.cleanup()
            conn.disconnect()
            self._cmd.info_logger.info(
                f"Successful cleaning at {rhost} with user: {user} and passwd: {passwd}"
            )
        except SCMRException:
            self._cmd.error_logger.error(
                f"Cannot delete files in {rhost}. Please restart Igris"
            )

    argParser = cmd2.Cmd2ArgumentParser(description="Tool to execute commands remotely")
    command_options = argParser.add_argument_group("Options for running commands")
    command_options.add_argument(
        "-C", "--command", help="Run a command on the windows machine."
    )
    command_options.add_argument(
        "-I",
        "--interactive",
        action="store_true",
        help="For an interactive cmd.exe or powershell.exe",
    )
    command_options.add_argument(
        "-ARG",
        "--arguments",
        help="""Arguments for a selected command. If there is more than one, 
        quotes must be used""",
    )
    command_options.add_argument(
        "-E",
        "--encryption",
        action="store_true",
        help="""Argument to encrypt the communication. Encryption does not 
        work with windows 7 and server 2008""",
    )
    command_options.add_argument(
        "-CL",
        "--clean_remote_files",
        action="store_true",
        help="Command to clean PaExec files on failure",
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

    @cmd2.with_argparser(argParser)
    def do_psexec(self, args: argparse.Namespace) -> None:
        """[Psexec is a command that allows remote execution on a windows machines]

        Args:
            args (argparse.Namespace): [Arguments passed to the  psexec command]
        """
        rhost = self._cmd.RHOST
        user = self._cmd.USER
        passwd = self._cmd.PASSWD

        settable_variables_required = {
            "RHOST": rhost,
            "USER": user,
            "PASSWD": passwd,
        }

        self._cmd.info_logger.debug(
            f"Starting psexec with the user {user} and the password {passwd} in {rhost}"
        )
        if args.show_settable:
            self._cmd.show_settable_variables_necessary(settable_variables_required)
            return
        if not self._cmd.check_settable_variables_value(settable_variables_required):
            return
        if args.clean_remote_files:
            self.__clean_paexec_files(args)
            return

        self.__process_to_perform_psexec(args)
