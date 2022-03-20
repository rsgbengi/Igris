from pypsexec.client import Client


class PsexecShellVariables:
    """[Class to group all the information to perform psexec]

    Args:
        conn (Client): [ Object with the current psexec connection ]
        executable (str): [ Program that will be executed Ej: cmd.exe or powershell.exe ]
        actual_work_dir (str, optional): [ Current directory to run executables]. Defaults to "C:\Windows\System32".
        possible_work_dir (str, optional): [ Directory to change in case of perform cd ]. Defaults to "C:\Windows\System32".
        shell_command (str , optional): [ Command run in  cmd.exe or powershell.exe]. Defaults to None."""

    def __init__(
        self,
        conn: Client,
        executable: str,
        actual_work_dir: str = "C:\\Windows\\System32",
        possible_work_dir: str = "C:\\Windows\\System32",
        shell_command: str = None,
    ) -> None:

        self.__conn = conn
        self.__actual_work_dir = actual_work_dir
        self.__possible_work_dir = possible_work_dir
        self.__executable = executable
        self.__shell_command = shell_command

    @property
    def conn(self) -> str:
        return self.__conn

    @property
    def actual_work_dir(self) -> str:
        return self.__actual_work_dir

    @property
    def possible_work_dir(self) -> str:
        return self.__possible_work_dir

    @property
    def executable(self) -> str:
        return self.__executable

    @property
    def shell_command(self) -> str:
        return self.__shell_command

    @shell_command.setter
    def shell_command(self, command: str) -> None:
        self.__shell_command = command

    @possible_work_dir.setter
    def possible_work_dir(self, possible_work_dir: str) -> None:
        self.__possible_work_dir = possible_work_dir

    @actual_work_dir.setter
    def actual_work_dir(self, actual_work_dir: str) -> None:
        self.__actual_work_dir = actual_work_dir
