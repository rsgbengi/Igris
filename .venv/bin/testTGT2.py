#!/home/rsgbengi/Igris/.venv/bin/python
# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Author: Alberto Solino (@agsolino)
#
from __future__ import division
from __future__ import print_function

import datetime
import logging
import random
from binascii import unhexlify

from pyasn1.codec.der import decoder, encoder

from impacket.krb5.crypto import _enctype_table
from impacket.dcerpc.v5.rpcrt import TypeSerialization1
from impacket.examples import logger
from impacket.krb5 import constants
from impacket.krb5.asn1 import AS_REP, TGS_REQ, AP_REQ, TGS_REP, Authenticator, AD_IF_RELEVANT, seq_set, \
    KERB_PA_PAC_REQUEST, \
    EncTGSRepPart, KERB_KEY_LIST_REQ, KERB_KEY_LIST_REP
from impacket.krb5.asn1 import EncTicketPart, Ticket as TicketASN
from impacket.krb5.ccache import CCache
from impacket.krb5.constants import EncryptionTypes
from impacket.krb5.crypto import Key
from impacket.krb5.kerberosv5 import sendReceive
from impacket.krb5.pac import KERB_VALIDATION_INFO, PAC_CLIENT_INFO, \
    PAC_SIGNATURE_DATA, PAC_INFO_BUFFER, PAC_CLIENT_INFO_TYPE, PAC_SERVER_CHECKSUM, \
    PAC_PRIVSVR_CHECKSUM, PACTYPE
from impacket.krb5.pac import PAC_UPN_DNS_INFO, UPN_DNS_INFO
from impacket.krb5.types import Principal, Ticket, KerberosTime
from impacket.structure import hexdump


################################################################################
# HELPER FUNCTIONS
################################################################################

def getFileTime(t):
    t *= 10000000
    t += 116444736000000000
    return t


class DECRYPTTGT:
    def __init__(self, options):
        self.__cacheFile = options.file
        self.__options = options
        self.__lmhash = ''
        self.__nthash = ''
        if options.hashes is not None:
            self.__lmhash, self.__nthash = options.hashes.split(':')
            self.__lmhash = unhexlify(self.__lmhash)
            self.__nthash = unhexlify(self.__nthash)

    def dump(self):
        ccache = CCache.loadFile(self.__cacheFile)
        ccache.prettyPrint()
        domain = ccache.principal.realm['data'].decode('utf-8')
        principal = 'krbtgt/%s@%s' % (domain.upper(), domain.upper())
        creds = ccache.getCredential(principal)
        if creds is not None:
            TGTCreds = creds.toTGT()
        tgt = TGTCreds['KDC_REP']
        cipher = TGTCreds['cipher']
        sessionKey = TGTCreds['sessionKey']

        decodedTGT = decoder.decode(tgt, asn1Spec=AS_REP())[0]
        print(decodedTGT.prettyPrint())
        print("=" * 80)

        ticket = decodedTGT['ticket']
        encryptedEncTicketPart = ticket['enc-part']
        print(encryptedEncTicketPart.prettyPrint())
        print("=" * 80)

        # if ticketEncPart['etype'] ==
        # AES-CBC-256 for now. ToDo, support all enctypes
        if encryptedEncTicketPart['etype'] == EncryptionTypes.aes256_cts_hmac_sha1_96.value:
            key = Key(cipher.enctype, unhexlify(self.__options.aesKey))
        elif encryptedEncTicketPart['etype'] == EncryptionTypes.aes128_cts_hmac_sha1_96.value:
            key = Key(cipher.enctype, unhexlify(self.__options.aesKey))
        elif encryptedEncTicketPart['etype'] == EncryptionTypes.rc4_hmac.value:
            key = Key(cipher.enctype, unhexlify(self.__options.nthash))

        # Key Usage 2
        # AS-REP Ticket and TGS-REP Ticket (includes TGS session
        # key or application session key), encrypted with the
        # service key (Section 5.3)
        logging.info('\tEncTicketPart')
        hexdump(encryptedEncTicketPart['cipher'])
        print("=" * 80)
        decryptedEncTicketPart = cipher.decrypt(key, 2, encryptedEncTicketPart['cipher'])
        hexdump(decryptedEncTicketPart)
        print("=" * 80)
        decodedEncTicketPart = decoder.decode(decryptedEncTicketPart, asn1Spec=EncTicketPart())[0]
        print(decodedEncTicketPart.prettyPrint())
        print("=" * 80)
        try:

            adIfRelevant = \
            decoder.decode(decodedEncTicketPart['authorization-data'][0]['ad-data'], asn1Spec=AD_IF_RELEVANT())[0]
        except:
            logging.debug("No PAC!")
        else:
            print(adIfRelevant.prettyPrint())
            print("=" * 80)
            # So here we have the PAC
            pacType = PACTYPE(adIfRelevant[0]['ad-data'].asOctets())
            buff = pacType['Buffers']

            for bufferN in range(pacType['cBuffers']):
                infoBuffer = PAC_INFO_BUFFER(buff)
                data = pacType['Buffers'][infoBuffer['Offset'] - 8:][:infoBuffer['cbBufferSize']]
                if logging.getLogger().level == logging.DEBUG:
                    print("TYPE 0x%x" % infoBuffer['ulType'])
                if infoBuffer['ulType'] == 1:
                    type1 = TypeSerialization1(data)
                    # I'm skipping here 4 bytes with its the ReferentID for the pointer
                    newdata = data[len(type1) + 4:]
                    kerbdata = KERB_VALIDATION_INFO()
                    kerbdata.fromString(newdata)
                    kerbdata.fromStringReferents(newdata[len(kerbdata.getData()):])
                    kerbdata.dump()
                    print()
                    print('Domain SID:', kerbdata['LogonDomainId'].formatCanonical())
                    print()
                elif infoBuffer['ulType'] == PAC_CLIENT_INFO_TYPE:
                    clientInfo = PAC_CLIENT_INFO(data)
                    if logging.getLogger().level == logging.DEBUG:
                        clientInfo.dump()
                        print()
                elif infoBuffer['ulType'] == PAC_SERVER_CHECKSUM:
                    signatureData = PAC_SIGNATURE_DATA(data)
                    if logging.getLogger().level == logging.DEBUG:
                        signatureData.dump()
                        print()
                elif infoBuffer['ulType'] == PAC_PRIVSVR_CHECKSUM:
                    signatureData = PAC_SIGNATURE_DATA(data)
                    if logging.getLogger().level == logging.DEBUG:
                        signatureData.dump()
                        print()
                elif infoBuffer['ulType'] == PAC_UPN_DNS_INFO:
                    upn = UPN_DNS_INFO(data)
                    if logging.getLogger().level == logging.DEBUG:
                        upn.dump()
                        print(data[upn['DnsDomainNameOffset']:])
                        print()
                else:
                    hexdump(data)

                if logging.getLogger().level == logging.DEBUG:
                    print("#" * 80)

                buff = buff[len(infoBuffer):]

        # cipherText = asRep['enc-part']['cipher']
        # plainText = cipher.decrypt (key, 3, cipherText)
        # encASRepPart = decoder.decode (plainText, asn1Spec=EncASRepPart ())[0]
        # authTime = encASRepPart['authtime']

        serverName = Principal('krbtgt_8073/%s' % domain.upper(),
                               type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        tgs, cipher, oldSessionKey, sessionKey = self.getKerberosTGS(serverName, domain, domain, tgt,
                                                                     cipher, sessionKey)

    def getKerberosTGS(self, serverName, domain, kdcHost, tgt, cipher, sessionKey, authTime=None):
        ## Get out Golden PAC
        # goldenPAC = self.getGoldenPAC (authTime)

        decodedTGT = decoder.decode(tgt, asn1Spec=AS_REP())[0]

        # Extract the ticket from the TGT
        ticket = Ticket()
        ticket.from_asn1(decodedTGT['ticket'])

        tgsReq = TGS_REQ()
        reqBody = seq_set(tgsReq, 'req-body')

        opts = list()
        opts.append(constants.KDCOptions.forwardable.value)
        opts.append(constants.KDCOptions.renewable.value)
        opts.append(constants.KDCOptions.proxiable.value)

        reqBody['kdc-options'] = constants.encodeFlags(opts)
        seq_set(reqBody, 'sname', serverName.components_to_asn1)
        reqBody['realm'] = decodedTGT['crealm'].prettyPrint()

        now = datetime.datetime.utcnow() + datetime.timedelta(days=1)

        reqBody['till'] = KerberosTime.to_asn1(now)
        reqBody['nonce'] = random.SystemRandom().getrandbits(31)

        apReq = AP_REQ()
        apReq['pvno'] = 5
        apReq['msg-type'] = int(constants.ApplicationTagNumbers.AP_REQ.value)

        opts = list()
        apReq['ap-options'] = constants.encodeFlags(opts)
        seq_set(apReq, 'ticket', ticket.to_asn1)

        authenticator = Authenticator()
        authenticator['authenticator-vno'] = 5
        authenticator['crealm'] = decodedTGT['crealm'].prettyPrint()

        clientName = Principal()
        clientName.from_asn1(decodedTGT, 'crealm', 'cname')

        seq_set(authenticator, 'cname', clientName.components_to_asn1)

        now = datetime.datetime.utcnow()
        authenticator['cusec'] = now.microsecond
        authenticator['ctime'] = KerberosTime.to_asn1(now)

        encodedAuthenticator = encoder.encode(authenticator)

        # Key Usage 7
        # TGS-REQ PA-TGS-REQ padata AP-REQ Authenticator (includes
        # TGS authenticator subkey), encrypted with the TGS session
        # key (Section 5.5.1)
        encryptedEncodedAuthenticator = cipher.encrypt(sessionKey, 7, encodedAuthenticator, None)

        apReq['authenticator'] = noValue
        apReq['authenticator']['etype'] = cipher.enctype
        apReq['authenticator']['cipher'] = encryptedEncodedAuthenticator

        encodedApReq = encoder.encode(apReq)

        tgsReq['pvno'] = 5
        tgsReq['msg-type'] = int(constants.ApplicationTagNumbers.TGS_REQ.value)
        tgsReq['padata'] = noValue
        tgsReq['padata'][0] = noValue
        tgsReq['padata'][0]['padata-type'] = int(constants.PreAuthenticationDataTypes.PA_TGS_REQ.value)
        tgsReq['padata'][0]['padata-value'] = encodedApReq

        pacRequest = KERB_PA_PAC_REQUEST()
        pacRequest['include-pac'] = True
        encodedPacRequest = encoder.encode(pacRequest)

        tgsReq['padata'][1] = noValue
        tgsReq['padata'][1]['padata-type'] = int(constants.PreAuthenticationDataTypes.PA_PAC_REQUEST.value)
        tgsReq['padata'][1]['padata-value'] = encodedPacRequest

        message = encoder.encode(tgsReq)

        r = sendReceive(message, domain, kdcHost)

        # Get the session key
        tgs = decoder.decode(r, asn1Spec=TGS_REP())[0]
        cipherText = tgs['enc-part']['cipher']

        # Key Usage 8
        # TGS-REP encrypted part (includes application session
        # key), encrypted with the TGS session key (Section 5.4.2)
        plainText = cipher.decrypt(sessionKey, 8, cipherText)

        encTGSRepPart = decoder.decode(plainText, asn1Spec=EncTGSRepPart())[0]

        newSessionKey = Key(cipher.enctype, encTGSRepPart['key']['keyvalue'].asOctets())

        return r, cipher, sessionKey, newSessionKey

    def dump2(self):
        fp = open('/root/GitHubProjects/impacket/examples/ticket.bin', 'rb')
        data = fp.read()
        hexdump(data)

        #tgsReq = decoder.decode(data[4:], asn1Spec=TGS_REQ)[0]
        print(tgsReq.prettyPrint())

        paData1 = tgsReq['padata'][0]
        # print(paData1.prettyPrint())
        encodedApReq = paData1['padata-value']
        apReq = decoder.decode(encodedApReq, asn1Spec=AP_REQ())[0]
        print(apReq.prettyPrint())
        print("=" * 80)

        ticket = apReq['ticket']
        encryptedEncTicketPart = ticket['enc-part']
        enctype = encryptedEncTicketPart['etype']
        print(encryptedEncTicketPart.prettyPrint())
        print("=" * 80)

        cipher = _enctype_table[enctype]
        # krbtgt
        krbtgtHash1 = b'5c0fad4175503e8d96fcd6a2e7227eae'
        aesKey1 = b'bd056fbf1b5faf2c9a2cb0276e5a6e9442ef4952c1b95de20626dc01e3f5a1dd'
        # krbtgt_18341
        krbtgtHash2 = b'a7a6c9a0346e4bd855301398581432ab'
        aesKey2 = b'63ae8c5ed215430d11017afa52bc3764b5c1faa501f0c6b50ffa9ada6bd3235a'
        # AzureADKerberos$
        krbtgtHash3 = b'56604c3bec5bccf623fb2f82aaf3b71c'
        aesKey3 = b'61183e11da9cdcd9aa137bc2d8f55c0c2e796521ee02f7697291f84eda1da3c0'

        # if ticketEncPart['etype'] ==
        # AES-CBC-256 for now. ToDo, support all enctypes
        if encryptedEncTicketPart['etype'] == EncryptionTypes.aes256_cts_hmac_sha1_96.value:
            key = Key(cipher.enctype, unhexlify(aesKey2))
        elif encryptedEncTicketPart['etype'] == EncryptionTypes.aes128_cts_hmac_sha1_96.value:
            key = Key(cipher.enctype, unhexlify(aesKey2))
        elif encryptedEncTicketPart['etype'] == EncryptionTypes.rc4_hmac.value:
            key = Key(cipher.enctype, unhexlify(krbtgtHash2))

        # Key Usage 2
        # AS-REP Ticket and TGS-REP Ticket (includes TGS session
        # key or application session key), encrypted with the
        # service key (Section 5.3)
        logging.info('\tEncTicketPart')
        hexdump(encryptedEncTicketPart['cipher'])
        print("=" * 80)

        decryptedEncTicketPart = cipher.decrypt(key, 2, encryptedEncTicketPart['cipher'])
        hexdump(decryptedEncTicketPart)
        print("=" * 80)

        decodedEncTicketPart = decoder.decode(decryptedEncTicketPart, asn1Spec=EncTicketPart())[0]
        print(decodedEncTicketPart.prettyPrint())
        print("=" * 80)

        #sessionkey = decodedEncTicketPart['key']['keyvalue'].asOctets()
        #print(sessionkey)

        try:
            adIfRelevant = \
            decoder.decode(decodedEncTicketPart['authorization-data'][0]['ad-data'], asn1Spec=AD_IF_RELEVANT())[0]
        except:
            logging.debug("No PAC!")
        else:
            print(adIfRelevant.prettyPrint())
            print("=" * 80)
            # So here we have the PAC
            pacType = PACTYPE(adIfRelevant[0]['ad-data'].asOctets())
            buff = pacType['Buffers']

            for bufferN in range(pacType['cBuffers']):
                infoBuffer = PAC_INFO_BUFFER(buff)
                data = pacType['Buffers'][infoBuffer['Offset'] - 8:][:infoBuffer['cbBufferSize']]
                if logging.getLogger().level == logging.DEBUG:
                    print("TYPE 0x%x" % infoBuffer['ulType'])
                if infoBuffer['ulType'] == 1:
                    type1 = TypeSerialization1(data)
                    # I'm skipping here 4 bytes with its the ReferentID for the pointer
                    newdata = data[len(type1) + 4:]
                    kerbdata = KERB_VALIDATION_INFO()
                    kerbdata.fromString(newdata)
                    kerbdata.fromStringReferents(newdata[len(kerbdata.getData()):])
                    kerbdata.dump()
                    print()
                    print('Domain SID:', kerbdata['LogonDomainId'].formatCanonical())
                    print()
                elif infoBuffer['ulType'] == PAC_CLIENT_INFO_TYPE:
                    clientInfo = PAC_CLIENT_INFO(data)
                    if logging.getLogger().level == logging.DEBUG:
                        clientInfo.dump()
                        print()
                elif infoBuffer['ulType'] == PAC_SERVER_CHECKSUM:
                    signatureData = PAC_SIGNATURE_DATA(data)
                    if logging.getLogger().level == logging.DEBUG:
                        signatureData.dump()
                        print()
                elif infoBuffer['ulType'] == PAC_PRIVSVR_CHECKSUM:
                    signatureData = PAC_SIGNATURE_DATA(data)
                    if logging.getLogger().level == logging.DEBUG:
                        signatureData.dump()
                        print()
                elif infoBuffer['ulType'] == PAC_UPN_DNS_INFO:
                    upn = UPN_DNS_INFO(data)
                    if logging.getLogger().level == logging.DEBUG:
                        upn.dump()
                        print(data[upn['DnsDomainNameOffset']:])
                        print()
                else:
                    hexdump(data)

                if logging.getLogger().level == logging.DEBUG:
                    print("#" * 80)

                buff = buff[len(infoBuffer):]

        print("=" * 80)
        encryptedAuth = apReq['authenticator']['cipher']
        print(encryptedAuth.prettyPrint())
        print("=" * 80)

        keyAuth = Key(cipher.enctype, bytes(decodedEncTicketPart['key']['keyvalue']))
        decryptedAuth = cipher.decrypt(keyAuth, 7, encryptedAuth)
        hexdump(decryptedAuth)
        print("*" * 80)
        decodedAuth = decoder.decode(decryptedAuth, asn1Spec=Authenticator())[0]
        print(decodedAuth.prettyPrint())
        print("=" * 80)

        paData2 = tgsReq['padata'][1]
        print(paData2.prettyPrint())
        decodedPaData2 = decoder.decode(paData2['padata-value'], asn1Spec=KERB_KEY_LIST_REQ())[0]
        print(decodedPaData2.prettyPrint())
        print("*" * 80)
        print("FIN 1")
        print("*" * 80)
        print("\n\n")

    def dump3(self):
        fp = open('/root/GitHubProjects/impacket/examples/t2.bin', 'rb')
        data = fp.read()
        hexdump(data)

        tgsRep = decoder.decode(data[4:], asn1Spec=TGS_REP())[0]
        print(tgsRep.prettyPrint())
        print("=" * 80)
        ticket = tgsRep['ticket']
        encryptedEncTicketPart = ticket['enc-part']
        enctype = encryptedEncTicketPart['etype']
        #print(encryptedEncTicketPart.prettyPrint())
        #print("=" * 80)

        cipher = _enctype_table[enctype]
        # krbtgt
        krbtgtHash1 = b'5c0fad4175503e8d96fcd6a2e7227eae'
        aesKey1 = b'bd056fbf1b5faf2c9a2cb0276e5a6e9442ef4952c1b95de20626dc01e3f5a1dd'
        # krbtgt_18341
        krbtgtHash2 = b'a7a6c9a0346e4bd855301398581432ab'
        aesKey2 = b'63ae8c5ed215430d11017afa52bc3764b5c1faa501f0c6b50ffa9ada6bd3235a'
        # AzureADKerberos$
        krbtgtHash3 = b'56604c3bec5bccf623fb2f82aaf3b71c'
        aesKey3 = b'61183e11da9cdcd9aa137bc2d8f55c0c2e796521ee02f7697291f84eda1da3c0'

        # if ticketEncPart['etype'] ==
        # AES-CBC-256 for now. ToDo, support all enctypes
        if encryptedEncTicketPart['etype'] == EncryptionTypes.aes256_cts_hmac_sha1_96.value:
            key = Key(cipher.enctype, unhexlify(aesKey1))
        elif encryptedEncTicketPart['etype'] == EncryptionTypes.aes128_cts_hmac_sha1_96.value:
            key = Key(cipher.enctype, unhexlify(aesKey1))
        elif encryptedEncTicketPart['etype'] == EncryptionTypes.rc4_hmac.value:
            key = Key(cipher.enctype, unhexlify(krbtgtHash1))

        # Key Usage 2
        # AS-REP Ticket and TGS-REP Ticket (includes TGS session
        # key or application session key), encrypted with the
        # service key (Section 5.3)
        #logging.info('\tEncTicketPart')
        #hexdump(encryptedEncTicketPart['cipher'])
        #print("=" * 80)

        decryptedEncTicketPart = cipher.decrypt(key, 2, encryptedEncTicketPart['cipher'])
        #hexdump(decryptedEncTicketPart)
        #print("=" * 80)

        decodedEncTicketPart = decoder.decode(decryptedEncTicketPart, asn1Spec=EncTicketPart())[0]
        print(decodedEncTicketPart.prettyPrint())
        print("=" * 80)

        flags = decodedEncTicketPart['flags']
        print(flags)
        print("=" * 80)

        # try:
        #     adIfRelevant = \
        #     decoder.decode(decodedEncTicketPart['authorization-data'][0]['ad-data'], asn1Spec=AD_IF_RELEVANT())[0]
        # except:
        #     logging.debug("No PAC!")
        # else:
        #     print(adIfRelevant.prettyPrint())
        #     print("=" * 80)
        #     # So here we have the PAC
        #     pacType = PACTYPE(adIfRelevant[0]['ad-data'].asOctets())
        #     buff = pacType['Buffers']
        #
        #     for bufferN in range(pacType['cBuffers']):
        #         infoBuffer = PAC_INFO_BUFFER(buff)
        #         data = pacType['Buffers'][infoBuffer['Offset'] - 8:][:infoBuffer['cbBufferSize']]
        #         if logging.getLogger().level == logging.DEBUG:
        #             print("TYPE 0x%x" % infoBuffer['ulType'])
        #         if infoBuffer['ulType'] == 1:
        #             type1 = TypeSerialization1(data)
        #             # I'm skipping here 4 bytes with its the ReferentID for the pointer
        #             newdata = data[len(type1) + 4:]
        #             kerbdata = KERB_VALIDATION_INFO()
        #             kerbdata.fromString(newdata)
        #             kerbdata.fromStringReferents(newdata[len(kerbdata.getData()):])
        #             kerbdata.dump()
        #             print()
        #             print('Domain SID:', kerbdata['LogonDomainId'].formatCanonical())
        #             print()
        #         elif infoBuffer['ulType'] == PAC_CLIENT_INFO_TYPE:
        #             clientInfo = PAC_CLIENT_INFO(data)
        #             if logging.getLogger().level == logging.DEBUG:
        #                 clientInfo.dump()
        #                 print()
        #         elif infoBuffer['ulType'] == PAC_SERVER_CHECKSUM:
        #             signatureData = PAC_SIGNATURE_DATA(data)
        #             if logging.getLogger().level == logging.DEBUG:
        #                 signatureData.dump()
        #                 print()
        #         elif infoBuffer['ulType'] == PAC_PRIVSVR_CHECKSUM:
        #             signatureData = PAC_SIGNATURE_DATA(data)
        #             if logging.getLogger().level == logging.DEBUG:
        #                 signatureData.dump()
        #                 print()
        #         elif infoBuffer['ulType'] == PAC_UPN_DNS_INFO:
        #             upn = UPN_DNS_INFO(data)
        #             if logging.getLogger().level == logging.DEBUG:
        #                 upn.dump()
        #                 print(data[upn['DnsDomainNameOffset']:])
        #                 print()
        #         else:
        #             hexdump(data)
        #
        #         if logging.getLogger().level == logging.DEBUG:
        #             print("#" * 80)
        #
        #         buff = buff[len(infoBuffer):]
#######
        encTGSRepPart = tgsRep['enc-part']
        print(encTGSRepPart.prettyPrint())
        enctype2 = encTGSRepPart['etype']

        cipher2 = _enctype_table[enctype2]
        #subkey = unhexlify(b'2671941bb6368dc6f08f65e9f465ec5280587b6897170da0740ab5bb1aee7f0f')
        subkey = unhexlify(b'78a42df39b6c441195590fd82a986faa9ed8e5077ba4b254a25f31463267c40d')
        #subkey = bytes(b'hgYvAaAVnvkRSpGNBIwgRiWHaPLQyFdD')
        subkey = Key(cipher2.enctype, subkey)

        decryptedTGSRepPart = cipher2.decrypt(subkey, 8, encTGSRepPart['cipher'])
        hexdump(decryptedTGSRepPart)
        print("=" * 80)

        decodedTGSRepPart = decoder.decode(decryptedTGSRepPart, asn1Spec=EncTGSRepPart())[0]
        print(decodedTGSRepPart.prettyPrint())
        print("=" * 80)

        encPaData1 = decodedTGSRepPart['encrypted_pa_data'][0]
        decodedPaData1 = decoder.decode(encPaData1['padata-value'], asn1Spec=KERB_KEY_LIST_REP())[0]
        print(decodedPaData1.prettyPrint())


        # encPaData2 = decodedTGSRepPart['encrypted_pa_data'][1]
        # decodedPaData2 = decoder.decode(encPaData2['padata-value'], asn1Spec=PA_SUPPORTED_ENCTYPES())[0]
        # print(decodedPaData2.prettyPrint())

######
    def dump4(self):
        fp = open('/root/GitHubProjects/impacket/examples/TGSREQ_11.bin', 'rb')
        data = fp.read()
        #hexdump(data)

        tgsReq = decoder.decode(data[4:], asn1Spec=TGS_REQ())[0]
        print(tgsReq.prettyPrint())

        paData1 = tgsReq['padata'][0]
        # print(paData1.prettyPrint())
        encodedApReq = paData1['padata-value']
        apReq = decoder.decode(encodedApReq, asn1Spec=AP_REQ())[0]
        print(apReq.prettyPrint())
        print("=" * 80)

        ticket = apReq['ticket']
        encryptedEncTicketPart = ticket['enc-part']
        enctype = encryptedEncTicketPart['etype']
        print(encryptedEncTicketPart.prettyPrint())
        print("=" * 80)

        cipher = _enctype_table[enctype]
        # krbtgt
        krbtgtHash1 = b'5c0fad4175503e8d96fcd6a2e7227eae'
        aesKey1 = b'bd056fbf1b5faf2c9a2cb0276e5a6e9442ef4952c1b95de20626dc01e3f5a1dd'
        # krbtgt_18341
        krbtgtHash2 = b'a7a6c9a0346e4bd855301398581432ab'
        aesKey2 = b'63ae8c5ed215430d11017afa52bc3764b5c1faa501f0c6b50ffa9ada6bd3235a'
        # AzureADKerberos$
        krbtgtHash3 = b'56604c3bec5bccf623fb2f82aaf3b71c'
        aesKey3 = b'61183e11da9cdcd9aa137bc2d8f55c0c2e796521ee02f7697291f84eda1da3c0'

        # if ticketEncPart['etype'] ==
        # AES-CBC-256 for now. ToDo, support all enctypes
        if encryptedEncTicketPart['etype'] == EncryptionTypes.aes256_cts_hmac_sha1_96.value:
            key = Key(cipher.enctype, unhexlify(aesKey1))
        elif encryptedEncTicketPart['etype'] == EncryptionTypes.aes128_cts_hmac_sha1_96.value:
            key = Key(cipher.enctype, unhexlify(aesKey1))
        elif encryptedEncTicketPart['etype'] == EncryptionTypes.rc4_hmac.value:
            key = Key(cipher.enctype, unhexlify(krbtgtHash1))

        # Key Usage 2
        # AS-REP Ticket and TGS-REP Ticket (includes TGS session
        # key or application session key), encrypted with the
        # service key (Section 5.3)
        #logging.info('\tEncTicketPart')
        #hexdump(encryptedEncTicketPart['cipher'])
        #print("=" * 80)

        decryptedEncTicketPart = cipher.decrypt(key, 2, encryptedEncTicketPart['cipher'])
        #hexdump(decryptedEncTicketPart)
        #print("=" * 80)

        decodedEncTicketPart = decoder.decode(decryptedEncTicketPart, asn1Spec=EncTicketPart())[0]
        print(decodedEncTicketPart.prettyPrint())
        print("=" * 80)

        flags = decodedEncTicketPart['flags']
        print(flags)
        print("=" * 80)

        # try:
        #     adIfRelevant = \
        #     decoder.decode(decodedEncTicketPart['authorization-data'][0]['ad-data'], asn1Spec=AD_IF_RELEVANT())[0]
        # except:
        #     logging.debug("No PAC!")
        # else:
        #     print(adIfRelevant.prettyPrint())
        #     print("=" * 80)
        #     # So here we have the PAC
        #     pacType = PACTYPE(adIfRelevant[0]['ad-data'].asOctets())
        #     buff = pacType['Buffers']
        #
        #     for bufferN in range(pacType['cBuffers']):
        #         infoBuffer = PAC_INFO_BUFFER(buff)
        #         data = pacType['Buffers'][infoBuffer['Offset'] - 8:][:infoBuffer['cbBufferSize']]
        #         if logging.getLogger().level == logging.DEBUG:
        #             print("TYPE 0x%x" % infoBuffer['ulType'])
        #         if infoBuffer['ulType'] == 1:
        #             type1 = TypeSerialization1(data)
        #             # I'm skipping here 4 bytes with its the ReferentID for the pointer
        #             newdata = data[len(type1) + 4:]
        #             kerbdata = KERB_VALIDATION_INFO()
        #             kerbdata.fromString(newdata)
        #             kerbdata.fromStringReferents(newdata[len(kerbdata.getData()):])
        #             kerbdata.dump()
        #             print()
        #             print('Domain SID:', kerbdata['LogonDomainId'].formatCanonical())
        #             print()
        #         elif infoBuffer['ulType'] == PAC_CLIENT_INFO_TYPE:
        #             clientInfo = PAC_CLIENT_INFO(data)
        #             if logging.getLogger().level == logging.DEBUG:
        #                 clientInfo.dump()
        #                 print()
        #         elif infoBuffer['ulType'] == PAC_SERVER_CHECKSUM:
        #             signatureData = PAC_SIGNATURE_DATA(data)
        #             if logging.getLogger().level == logging.DEBUG:
        #                 signatureData.dump()
        #                 print()
        #         elif infoBuffer['ulType'] == PAC_PRIVSVR_CHECKSUM:
        #             signatureData = PAC_SIGNATURE_DATA(data)
        #             if logging.getLogger().level == logging.DEBUG:
        #                 signatureData.dump()
        #                 print()
        #         elif infoBuffer['ulType'] == PAC_UPN_DNS_INFO:
        #             upn = UPN_DNS_INFO(data)
        #             if logging.getLogger().level == logging.DEBUG:
        #                 upn.dump()
        #                 print(data[upn['DnsDomainNameOffset']:])
        #                 print()
        #         else:
        #             hexdump(data)
        #
        #         if logging.getLogger().level == logging.DEBUG:
        #             print("#" * 80)
        #
        #         buff = buff[len(infoBuffer):]


if __name__ == '__main__':
    import argparse
    import sys

    try:
        import pyasn1
        from pyasn1.type.univ import noValue
    except ImportError:
        logging.critical('This module needs pyasn1 installed')
        logging.critical('You can get it from https://pypi.python.org/pypi/pyasn1')
        sys.exit(1)
    from impacket import version

    print(version.BANNER)

    parser = argparse.ArgumentParser(add_help=True)

    parser.add_argument('-file', action='store', help='Adds timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar="LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-aesKey', action="store", metavar="hex key",
                       help='AES key to use for decryption (128 or 256 bits)')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    # Init the example's logger theme
    logger.init(options.ts)

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    dumper = DECRYPTTGT(options)

    try:
        #dumper.dump2()
        dumper.dump3()
        #dumper.dump4()
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback

            traceback.print_exc()
        logging.critical(str(e))
