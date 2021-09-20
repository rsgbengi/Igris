from pypsexec.client import Client


class PsexecShellVariables:
    """[Class to group all the information to perform psexec]

    Args:
        _conn (Client): [ Object with the current psexec connection ]
        _executable (str): [ Program that will be executed Ej: cmd.exe or powershell.exe ]
        _actual_work_dir (str, optional): [ Current directory to run executables]. Defaults to "C:\Windows\System32".
        _possible_work_dir (str, optional): [ Directory to change in case of perform cd ]. Defaults to "C:\Windows\System32".
        _shell_command (str , optional): [ Command run in  cmd.exe or powershell.exe]. Defaults to None."""

    def __init__(
        self,
        _conn: Client,
        _executable: str,
        _actual_work_dir: str = "C:\\Windows\\System32",
        _possible_work_dir: str = "C:\\Windows\\System32",
        _shell_command: str = None,
    ) -> None:

        self._conn = _conn
        self._actual_work_dir = _actual_work_dir
        self._possible_work_dir = _possible_work_dir
        self._executable = _executable
        self._shell_command = _shell_command

    @property
    def conn(self) -> str:
        return self._conn

    @property
    def actual_work_dir(self) -> str:
        return self._actual_work_dir

    @property
    def possible_work_dir(self) -> str:
        return self._possible_work_dir

    @property
    def executable(self) -> str:
        return self._executable

    @property
    def shell_command(self) -> str:
        return self._shell_command

    @shell_command.setter
    def shell_command(self, command: str) -> None:
        self._shell_command = command

    @possible_work_dir.setter
    def possible_work_dir(self, possible_work_dir: str) -> None:
        self._possible_work_dir = possible_work_dir

    @actual_work_dir.setter
    def actual_work_dir(self, actual_work_dir: str) -> None:
        self._actual_work_dir = actual_work_dir
