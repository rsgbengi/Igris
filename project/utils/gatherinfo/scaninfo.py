from cmd2 import ansi
from multiprocessing import Manager
import json


class UserInfo:
    """[ Credentials for the user ]

    Args:
        user (str): [ User credential ]
        passwd (str): [ Passwd credential ]
        psexec (bool, optional): [ To check possibility of psexec]. Defaults to False.
    """

    def __init__(self, user: str, passwd: str, psexec: bool = False) -> None:

        self.__user = user
        self.__passwd = passwd
        self.__psexec = psexec

    @property
    def user(self):
        return self.__user

    @property
    def passwd(self):
        return self.__passwd

    @property
    def psexec(self) -> None:
        return self.__psexec

    @psexec.setter
    def psexec(self, psexec: bool) -> bool:
        self.__psexec = psexec

    def psexec_info(self) -> str:
        if self.__psexec:
            return "PsExec here!"
        else:
            return "Not PsExec here!"

    def __eq__(self, user_to_compare) -> bool:
        if not isinstance(user_to_compare, UserInfo):
            return NotImplemented
        return (
            self.__user == user_to_compare.user
            and self.__passwd == user_to_compare.passwd
        )


class TargetInfo:
    """[ Class for grouping information to scan a subnet]

    Args:
        ip (str): [ ip target of the current machine ]
        os (str, optional): [ Operating System of the target ]. Defaults to None.
        signed (bool, optional): [ To check possibility of doing psexec ]. Defaults to None.
        computer_name (str, optional): [ Name of the remote pc ]. Defaults to None.
    """

    def __init__(
        self,
        ip: str,
        os: str = None,
        signed: bool = None,
        computer_name: str = None,
    ) -> None:

        self.__os = os
        self.__signed = signed
        self.__computer_name = computer_name
        self.__ip = ip
        self.__users = {}

    @property
    def users(self) -> None:
        return self.__users

    @property
    def ip(self) -> None:
        return self.__ip

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
        self.__os = os

    @users.setter
    def users(self, user: UserInfo) -> None:
        self.__users[user.user + user.passwd] = user

    @signed.setter
    def signed(self, signed: bool) -> bool:
        self.__signed = signed

    @computer_name.setter
    def computer_name(self, computer_name: str) -> str:
        self.__computer_name = computer_name


class SubnetInfo:
    def __init__(self, subnet: str):
        self.__subnet = subnet
        self.__computers = Manager().list()
        self.__users_used = []

    @property
    def computers(self) -> Manager().list():
        return self.__computers

    @property
    def users_used(self) -> list:
        return self.__users_used

    @computers.setter
    def computers(self, new_computer: TargetInfo):
        self.__computers.append(new_computer)

    def add_computer(self, computer: TargetInfo) -> None:
        self.__computers.append(computer)

    def add_new_user(self, user: UserInfo) -> None:
        self.__users_used.append(user)

    def check_if_user_exits(self, user: UserInfo) -> bool:
        return user in self.__users_used

    def casting_to_list_computers(self):
        self.__computers = list(self.__computers)
    def casting_to_manager_list_computers(self):
        self.__computers = Manager().list(self.__computers)
