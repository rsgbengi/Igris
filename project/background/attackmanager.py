import argparse
from multiprocessing import Process
from threading import Thread
import sys
import signal


class AttackManager:
    def __init__(
        self, attack_process: Process, name: str, alerts_hunter: Thread, alerts: dict
    ) -> None:
        self.__attack_process = attack_process
        self.__name = name
        self.__alerts_hunter = alerts_hunter
        self.__alerts_dictionary = alerts
    @proeperty

    def start_attack(self, launch_attack: function, args: argparse.Namespace):
        self.__attack_process = Process(target=launch_attack, args=(args,))
        try:
            self.__attack_process.start()
            if not args.Asynchronous:
                self.__attack_process.join()
        except KeyboardInterrupt:
            self.__finish_process()
            # self._cmd.active_attacks_configure(f"{self.__name}", False)

    def __ends_alerts_hunter(self):
        if self.__alerts_hunter is not None and self.__alerts_hunter.is_alive():
            self._cmd.info_logger.debug("Finishing alerts thread ...")
            self.__alerts_dictionary["stop"] = 1
            self.__alerts_hunter.join()
            self.__alerts_dictionary["stop"] = 0

    def ends_attack(self) -> None:
        """[ Method to terminate the attack by the user ]"""
        if self.__attack_process is not None and self.__attack_process.is_alive:
            self._cmd.info_logger.success(
                f"Finishing {self.__name} attack in the background ..."
            )
            self.__finish_process()
            # self._cmd.active_attacks_configure("NTLM_Relay", False)
            self.__ends_alerts_hunter()
            # Tal vez deberia devolver bool para saber si se ha terminado guay para cambiar status
            # de los ataques

        else:
            self._cmd.error_logger.error(
                "There is not {self.__name} process in the background"
            )

    def check_process_status(self) -> bool:
        if self.__attack_process.is_alive():
            self._cmd.error_logger.warning(
                "The attacks is already running in the background "
            )
            return False
        return True

    def async_options(self, asynchronouos: bool):
        if asynchronouos:
            sys.stdout = open("/dev/null", "w")
            signal.signal(signal.SIGINT, signal.SIG_IGN)

    def __finish_process(self):
        self.__attack_process.terminate()
        self.__attack_process.join()
        self.__attack_process = None
