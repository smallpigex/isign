#
# This is a Construct library which represents an
# LC_CODE_SIGNATURE structure. Like all Construct
# libraries, can be used for parsing or emitting
# (Construct calls it 'building')
#


from construct import *
import plistlib
import logging

from pyasn1.codec.der.decoder import decode
from pyasn1.codec.der.encoder import encode
import ents

SHA1_HASHTYPE = 1
SHA256_HASHTYPE = 2

log = logging.getLogger(__name__)
'''
FOR NOW we do not use an adapter; instead, will handle localy
'''


class Asn1Adapter(Adapter):
    def _encode(self, obj, context):
        return encode(obj)

    def _decode(self, obj, context):
        #    log.info('Decoding obj %s : %s', type(obj), obj)
        ent, rest = decode(obj, ents.Ents())
        #    log.info('Decoded asn %s', type(ent))
        # traceback.print_stack(file=sys.stdout)
        #  for field in ent:
        #     log.info('Key %s value %s', field['key'], field['val'])
        return ent


class PlistAdapter(Adapter):
    def _encode(self, obj, context):
        return plistlib.writePlistToString(obj)

    def _decode(self, obj, context):
        obj = plistlib.readPlistFromString(obj)
        #    log.info('Decoded xml %s', type(obj))
        #  traceback.print_stack(file=sys.stdout)
        #  for key in obj.keys():
        #      log.info('Key %s value %s', key, obj[key])
        return obj


# talk about overdesign.
# magic is in the blob struct

Expr = LazyBound("expr", lambda: Expr_)
Blob = LazyBound("blob", lambda: Blob_)

Hashes = LazyBound("hashes", lambda: Hashes_)
Hashes_ = Array(lambda ctx: ctx['nSpecialSlots'] + ctx['nCodeSlots'], Bytes("hash", lambda ctx: ctx['hashSize']))

CodeDirectory = Struct("CodeDirectory",
                       Anchor("cd_start"),
                       UBInt32("version"),
                       UBInt32("flags"),
                       UBInt32("hashOffset"),
                       UBInt32("identOffset"),
                       UBInt32("nSpecialSlots"),
                       UBInt32("nCodeSlots"),
                       UBInt32("codeLimit"),
                       UBInt8("hashSize"),
                       UBInt8("hashType"),
                       UBInt8("platform"),
                       UBInt8("pageSize"),
                       UBInt32("spare2"),
                       UBInt32("scatterOffset"),
                       UBInt32("teamIDOffset"),
                       Pointer(lambda ctx: ctx['cd_start'] - 8 + ctx['identOffset'], CString('ident')),

                       If(lambda ctx: ctx['version'] >= 0x20300, UBInt32("spare3")),
                       If(lambda ctx: ctx['version'] >= 0x20300, UBInt64("codeLimit64")),
                       If(lambda ctx: ctx['version'] >= 0x20400, UBInt64("execSegBase")),
                       If(lambda ctx: ctx['version'] >= 0x20400, UBInt64("execSegLimit")),
                       If(lambda ctx: ctx['version'] >= 0x20400, UBInt64("execSegFlags")),
                       Pointer(lambda ctx: ctx['cd_start'] - 8 + ctx['teamIDOffset'], CString('teamID')),
                       Pointer(
                           lambda ctx: ctx['cd_start'] - 8 + ctx['hashOffset'] - ctx['hashSize'] * ctx['nSpecialSlots'],
                           Hashes)
                       )

Data = Struct("Data",
              UBInt32("length"),
              Bytes("data", lambda ctx: ctx['length']),
              Padding(lambda ctx: -ctx['length'] & 3),
              )

CertSlot = Enum(UBInt32("slot"),
                anchorCert=-1,
                leafCert=0,
                _default_=Pass,
                )

Match = Struct("Match",
               Enum(UBInt32("matchOp"),
                    matchExists=0,
                    matchEqual=1,
                    matchContains=2,
                    matchBeginsWith=3,
                    matchEndsWith=4,
                    matchLessThan=5,
                    matchGreaterThan=6,
                    matchLessEqual=7,
                    matchGreaterEqual=8,
                    ),
               If(lambda ctx: ctx['matchOp'] != 'matchExists', Data)
               )

expr_args = {
    'opIdent': Data,
    'opAnchorHash': Sequence("AnchorHash", CertSlot, Data),
    'opInfoKeyValue': Data,
    'opAnd': Sequence("And", Expr, Expr),
    'opOr': Sequence("Or", Expr, Expr),
    'opNot': Expr,
    'opCDHash': Data,
    'opInfoKeyField': Sequence("InfoKeyField", Data, Match),
    'opEntitlementField': Sequence("EntitlementField", Data, Match),
    'opCertField': Sequence("CertField", CertSlot, Data, Match),
    'opCertGeneric': Sequence("CertGeneric", CertSlot, Data, Match),
    'opTrustedCert': CertSlot,
}

Expr_ = Struct("Expr",
               Enum(UBInt32("op"),
                    opFalse=0,
                    opTrue=1,
                    opIdent=2,
                    opAppleAnchor=3,
                    opAnchorHash=4,
                    opInfoKeyValue=5,
                    opAnd=6,
                    opOr=7,
                    opCDHash=8,
                    opNot=9,
                    opInfoKeyField=10,
                    opCertField=11,
                    opTrustedCert=12,
                    opTrustedCerts=13,
                    opCertGeneric=14,
                    opAppleGenericAnchor=15,
                    opEntitlementField=16,
                    ),
               Switch("data", lambda ctx: ctx['op'],
                      expr_args,
                      default=Pass),
               )

Requirement = Struct("Requirement",
                     Const(UBInt32("kind"), 1),
                     Expr,
                     )

Entitlement = Struct("Entitlement",
                     # actually a plist
                     PlistAdapter(Bytes("data", lambda ctx: ctx['_']['length'] - 8)),
                     )

EntitlementBinary = Struct("EntitlementBinary",
                           # actually a DER encoded entitlement
                           Asn1Adapter(Bytes("data", lambda ctx: ctx['_']['length'] - 8)),
                           )

EntitlementsBlobIndex = Struct("BlobIndex",
                               Enum(UBInt32("type"),
                                    kSecHostRequirementType=1,
                                    kSecGuestRequirementType=2,
                                    kSecDesignatedRequirementType=3,
                                    kSecLibraryRequirementType=4,
                                    ),
                               UBInt32("offset"),
                               Pointer(lambda ctx: ctx['_']['sb_start'] - 8 + ctx['offset'], Blob),
                               )

Entitlements = Struct("Entitlements",  # actually a kind of super blob
                      Anchor("sb_start"),
                      UBInt32("count"),
                      Array(lambda ctx: ctx['count'], EntitlementsBlobIndex),
                      #	Probe(),
                      )

BlobWrapper = Struct("BlobWrapper",
                     OnDemand(Bytes("data", lambda ctx: ctx['_']['length'] - 8)),
                     )

BlobIndex = Struct("BlobIndex",
                   UBInt32("type"),
                   UBInt32("offset"),
                   If(lambda ctx: ctx['offset'], Pointer(lambda ctx: ctx['_']['sb_start'] - 8 + ctx['offset'], Blob)),
                   #	Probe(),
                   )

SuperBlob = Struct("SuperBlob",
                   Anchor("sb_start"),
                   UBInt32("count"),
                   Array(lambda ctx: ctx['count'], BlobIndex),
                   #  Probe(),
                   )

Blob_ = Struct("Blob",
               Enum(UBInt32("magic"),
                    CSMAGIC_REQUIREMENT=0xfade0c00,
                    CSMAGIC_REQUIREMENTS=0xfade0c01,
                    CSMAGIC_CODEDIRECTORY=0xfade0c02,
                    CSMAGIC_ENTITLEMENT=0xfade7171,
                    # actually, this is kSecCodeMagicEntitlement, and not defined in the C version
                    CSMAGIC_ENTITLEMENT_BINARY=0xfade7172,
                    CSMAGIC_BLOBWRAPPER=0xfade0b01,
                    # and this isn't even defined in libsecurity_codesigning; it's in _utilities
                    CSMAGIC_EMBEDDED_SIGNATURE=0xfade0cc0,
                    CSMAGIC_DETACHED_SIGNATURE=0xfade0cc1,
                    CSMAGIC_CODE_SIGN_DRS=0xfade0c05,
                    ),
               UBInt32("length"),
               Peek(Switch("data", lambda ctx: ctx['magic'],
                           {'CSMAGIC_REQUIREMENT': Requirement,
                            'CSMAGIC_REQUIREMENTS': Entitlements,
                            'CSMAGIC_CODEDIRECTORY': CodeDirectory,
                            'CSMAGIC_ENTITLEMENT': Entitlement,
                            'CSMAGIC_ENTITLEMENT_BINARY': EntitlementBinary,
                            'CSMAGIC_BLOBWRAPPER': BlobWrapper,
                            'CSMAGIC_EMBEDDED_SIGNATURE': SuperBlob,
                            'CSMAGIC_DETACHED_SIGNATURE': SuperBlob,
                            'CSMAGIC_CODE_SIGN_DRS': SuperBlob,
                            })),
               OnDemand(Bytes('bytes', lambda ctx: ctx['length'] - 8)),
               )
