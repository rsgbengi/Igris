#!/usr/bin/env python3
from multiprocessing import Process, Manager
from threading import Thread

from loguru import logger
import sys
import signal


class AttackManager:
    def __init__(
        self,
        attack_process: Process,
        info_logger: logger,
        error_logger: logger,
        alerts_hunter: Thread = None,
        alerts_dictionary: Manager().dict() = None,
    ):
        self._attack_process = attack_process
        self._alerts_hunter = alerts_hunter
        self._alerts_dictionary = alerts_dictionary
        self.__info_logger = info_logger
        self.__error_logger = error_logger

    def end_process_in_the_background(self):
        """[ Method to stop the attack by the user ]"""
        if self._attack_process is not None and self._attack_process.is_alive:
            self.__info_logger.success("Finishing attack in the background ...")
            self._attack_process.terminate()
            self._attack_process.join()
            self._attack_process = None
            if self._alerts_hunter is not None and self._alerts_hunter.is_alive():
                self._alerts_dictionary["stop"] = 1
                self._alerts_hunter.join()
                self._alerts_dictionary["stop"] = 0
        else:
            self.__error_logger.error("Not background process found ")

    def configure_alerts_thread(self, display_alerts):
        """[ Method to configure the thread that shows alerts ]"""
        type(display_alerts)
        self._alerts_hunter = Thread(target=display_alerts)
        self._alerts_hunter.dameon = True
        self._alerts_hunter.start()

    def async_options(self):
        """[ Configuration in case of an asynchronous attack ]"""
        sys.stdout = open("/dev/null", "w")
        signal.signal(signal.SIGINT, signal.SIG_IGN)

    def synchronous_attack(self):
        """[ Method to perform the attack synchronously ]"""
        try:
            self._attack_process.join()
        except KeyboardInterrupt:
            self._attack_process.terminate()
            self._attack_process.join()
            self._attack_process = None
            self.__error_logger.warning("Exiting attack ...")
