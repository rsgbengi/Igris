#!/usr/bin/env python
# -*- coding: utf-8 -*-
from impacket import smbserver
from impacket.examples import logger

def startSMBServer():
    logger.init(False)
    server = smbserver.SimpleSMBServer()
    server.setSMBChallenge('')
    server.start()
