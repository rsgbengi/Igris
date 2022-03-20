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
    def user(self) -> str:
        return self.__user

    @property
    def passwd(self) -> str:
        return self.__passwd


class TargetInfo:
    """[ Class for grouping information to scan a subnet]

    Args:
        ip (str): [ ip target of the current machine ]
        os (str, optional): [ Operating System of the target ]. Defaults to None.
        signed (bool, optional): [ To check possibility of doing psexec ]. Defaults to None.
        computer_name (str, optional): [ Name of the remote pc ]. Defaults to None.
        psexec (bool, optional): [ To check possibility of psexec]. Defaults to False.
    """

    def __init__(
        self,
        ip: str,
        os: str = None,
        signed: bool = None,
        computer_name: str = None,
        subnet: str = None,
        psexec: bool = None,
    ) -> None:

        self.__os = os
        self.__signed = signed
        self.__computer_name = computer_name
        self.__ip = ip
        self.__subnet = subnet
        self.__psexec = psexec

    @property
    def ip(self) -> str:
        return self.__ip

    @property
    def os(self) -> str:
        return self.__os

    @property
    def computer_name(self) -> str:
        return self.__computer_name

    @property
    def signed(self) -> bool:
        return self.__signed

    @property
    def psexec(self) -> bool:
        return self.__psexec

    @property
    def subnet(self) -> str:
        return self.__subnet

    @os.setter
    def os(self, os: str) -> None:
        self.__os = os

    @signed.setter
    def signed(self, signed: bool) -> None:
        self.__signed = signed

    @computer_name.setter
    def computer_name(self, computer_name: str) -> None:
        self.__computer_name = computer_name

    @psexec.setter
    def psexec(self, psexec: bool) -> None:
        self.__psexec = psexec

    @subnet.setter
    def subnet(self, subnet: str) -> None:
        self.__subnet = subnet

    @property
    def login_possibility(self) -> bool:
        return self.__login_possibility

    def psexec_info(self) -> str:
        return "PsExec here!" if self.__psexec else "Not PsExec here!"
