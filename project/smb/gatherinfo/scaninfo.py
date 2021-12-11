from cmd2 import ansi


class UserInfo:
    """[ Credentials for the user ]

    Args:
        user (str): [ User credential ]
        passwd (str): [ Passwd credential ]
    """

    def __init__(self, user: str, passwd: str) -> None:

        self.__user = user
        self.__passwd = passwd

    @property
    def user(self):
        return self.__user

    @property
    def passwd(self):
        return self.__passwd


class TargetInfo:
    """[ Class for grouping information to scan a subnet]

    Args:
        ip (str): [ ip target of the current machine ]
        subnet (str): [ current subnet target ]
        user_info (UserInfo): [ user credentials ]
        os (str, optional): [ Operating System of the target ]. Defaults to None.
        signed (bool, optional): [ To check possibility of doing psexec ]. Defaults to None.
        computer_name (str, optional): [ Name of the remote pc ]. Defaults to None.
        psexec (bool, optional): [ To check possibility of psexec]. Defaults to False.
    """

    def __init__(
        self,
        ip: str,
        subnet: str,
        user_info: UserInfo,
        os: str = None,
        signed: bool = None,
        computer_name: str = None,
        psexec: bool = False,
    ) -> None:

        self.__subnet = subnet
        self.__os = os
        self.__signed = signed
        self.__computer_name = computer_name
        self.__ip = ip
        self.__user_info = user_info
        self.__psexec = psexec

    @property
    def user_info(self) -> None:
        return self.__user_info

    @property
    def subnet(self) -> None:
        return self.__subnet

    @property
    def ip(self) -> None:
        return self.__ip

    @property
    def psexec(self) -> None:
        return self.__psexec

    @property
    def os(self) -> None:
        return self.__os

    @property
    def computer_name(self) -> None:
        return self.__computer_name

    @property
    def signed(self) -> None:
        return self.__signed

    @os.setter
    def os(self, os: str) -> None:
        self.__os = ansi.style(os, fg=ansi.fg.bright_magenta)

    @signed.setter
    def signed(self, signed: bool) -> bool:
        self.__signed = ansi.style(signed, fg=ansi.fg.bright_magenta)

    @computer_name.setter
    def computer_name(self, computer_name: str) -> str:
        self.__computer_name = ansi.style(computer_name, fg=ansi.fg.bright_magenta)

    @psexec.setter
    def psexec(self, psexec: bool) -> bool:
        self.__psexec = psexec
