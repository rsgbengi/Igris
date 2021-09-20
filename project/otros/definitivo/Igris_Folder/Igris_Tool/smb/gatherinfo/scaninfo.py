from cmd2 import ansi


class UserInfo:
    """[ Credentials for the user ]

    Args:
        user (str): [ User credential ]
        passwd (str): [ Passwd credential ]
    """

    def __init__(self, user: str, passwd: str) -> None:

        self._user = user
        self._passwd = passwd

    @property
    def user(self):
        return self._user

    @property
    def passwd(self):
        return self._passwd


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

        self._subnet = subnet
        self._os = os
        self._signed = signed
        self._computer_name = computer_name
        self._ip = ip
        self._user_info = user_info
        self._psexec = psexec

    @property
    def user_info(self) -> None:
        return self._user_info

    @property
    def subnet(self) -> None:
        return self._subnet

    @property
    def ip(self) -> None:
        return self._ip

    @property
    def psexec(self) -> None:
        return self._psexec

    @property
    def os(self) -> None:
        return self._os

    @property
    def computer_name(self) -> None:
        return self._computer_name

    @property
    def signed(self) -> None:
        return self._signed

    @os.setter
    def os(self, os: str) -> None:
        self._os = ansi.style(os, fg=ansi.fg.bright_magenta)

    @signed.setter
    def signed(self, signed: bool) -> bool:
        self._signed = ansi.style(signed, fg=ansi.fg.bright_magenta)

    @computer_name.setter
    def computer_name(self, computer_name: str) -> str:
        self._computer_name = ansi.style(computer_name, fg=ansi.fg.bright_magenta)

    @psexec.setter
    def psexec(self, psexec: bool) -> bool:
        self._psexec = psexec
