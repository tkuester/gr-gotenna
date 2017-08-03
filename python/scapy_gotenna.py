from scapy.all import *

# Constants
# ---------------------
_PKT_TYPES = { 0x11: 'broadcast_syn',
               0x10: 'dm_syn',
               0x62: 'dm_synack',
               0x23: 'ident',
               0x34: 'ident_ack',
               0x45: 'msg_frag',
               0x56: 'msg_ack',
               }

_FRAME_TYPES = { 0x01: 'whoami',
                 0x02: 'pubkey',
                 0x03: 'payload fragment',
                 }

_PLD_FRAME_TYPES = { 0x03: 'initials',
                     0x04: 'message',
                     0x06: 'location',
                     0x07: 'hilight',
                     0x08: 'latitude',
                     0x09: 'longitude',
                     0x13: 'timestamp',
                     0xfb: 'source id',
                     0xfc: 'pubkey',
                     }

# Formatters
# ---------------------
def str2gid(s):
    gid = int(s.encode('hex'), 16)
    if gid < 9999999999 and gid != 0:
        gid = '%010d' % gid
        gid = '(%s)%s-0000' % (gid[0:3], gid[3:6])
    elif gid <= 19999999999 and gid != 0:
        gid = '%011d' % gid
        gid = '+%s (%s)%s-0000' % (gid[0], gid[1:4], gid[4:7])
    else:
        gid = '%014d' % gid
        gid = ' '.join([gid[0:4], '0000', gid[8:12], '00'])

    return gid

def gid2str(gid):
    gid = filter(lambda ch: ch in '1234567890', gid)
    if gid == '':
        return b'\x00' * 6
    gid = int(gid, 10)
    gid = ('%012x' % gid).decode('hex')
    return gid

# Custom Fields
# ---------------------
class GotennaGIDField(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, '6s')

    def i2m(self, pkt, x):
        return gid2str(x)

    def m2i(self, pkt, x):
        if x is None:
            x = b'\x00' * 6
        return str2gid(x)

class SaveRoomPacketListField(PacketListField):
    '''
    We don't know what the length of the packet list is. However,
    we know the last 10 bytes are the sig, and hash. So just keep
    going until we have 10 bytes left.

    Lifted this code straight out of scapy/fields.py
    '''
    __slots__ = ['pad_len']
    def __init__(self, name, default, cls, pad_len):
        super(SaveRoomPacketListField, self).__init__(name, default, cls, length_from=lambda x: None)
        self.pad_len = pad_len

    def getfield(self, pkt, s):
        lst = []
        remain = s

        # keep going while remain > 10
        while len(remain) > self.pad_len:
            try:
                p = self.m2i(pkt,remain)
            except StandardError:
                if conf.debug_dissector:
                    raise
                p = conf.raw_layer(load=remain)
                remain = ""
            else:
                if conf.padding_layer in p:
                    pad = p[conf.padding_layer]
                    remain = pad.load
                    del(pad.underlayer.payload)
                else:
                    remain = ""
            lst.append(p)
        return remain, lst

# RF Packets
# ---------------------
class Gotenna(Packet):
    name = 'gotenna'
    fields_desc = [ ByteEnumField('type', None, _PKT_TYPES) ]

class Control(Packet):
    name = 'ctrl'
    fields_desc = [ XByteField('unk0', None),
                    BitField('next_chan', None, 4),
                    BitField('unk1', None, 4),
                    XShortField('hash16', None),
                    XShortField('hash16_2', None),
                    XByteField('unk2', None),
                    StrFixedLenField('sig', "", length=8),
                    XShortField('csum', None)
                    ]

class GotennaFrame(Packet):
    name = 'frame'
    fields_desc = [ ByteEnumField('type', None, _FRAME_TYPES),
                    FieldLenField('len', None, length_of='data', fmt='B'),
                    StrLenField('data', '', length_from=lambda p: p.len),
                    StrFixedLenField('sig2', '', length=8),
                    XShortField('hash2', None),
                    ]

    def extract_padding(self, pay):
        return "",pay

    registered_options = {}
    @classmethod
    def register_variant(cls):
        cls.registered_options[cls.type.default] = cls
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt:
            o = ord(_pkt[0])
            return cls.registered_options.get(o, cls)
        return cls

class DataHeader(Packet):
    name = 'data'
    #
    fields_desc = [ XByteField('unk1', None),
                    FlagsField("flags", 0, 8, ["f0", "plaintext", "f2", "f3", "f4", "f5", "f6", "f7"]),
                    XShortField('seq', None),
                    XShortField('convo_id', None),
                    XByteField('unk2', None),
                    StrFixedLenField('sig', '', length=8),
                    XShortField('hash', None),
                    PacketField('frame', None, GotennaFrame),
                    ]

class IdentFrame(GotennaFrame):
    name = 'ident'
    fields_desc = [ ByteEnumField('type', 0x01, _FRAME_TYPES),
                    XByteField('len', 0x09),
                    XShortField('bcast', 0x3fff),
                    GotennaGIDField('gid', ''),
                    XByteField('unk', 0x00),
                    StrFixedLenField('sig', '', length=8),
                    XShortField('hash', None),
                    ]

class KeyExchangeFrame(GotennaFrame):
    name = 'pubkey'
    fields_desc = [ ByteEnumField('type', 0x02, _FRAME_TYPES),
                    FieldLenField('len', 0x31, length_of='key', fmt='B'),
                    StrLenField('pubkey', '', length_from=lambda pkt: pkt.len),
                    StrFixedLenField('sig', '', length=8),
                    XShortField('hash', None),
                    ]

class PayloadFragment(GotennaFrame):
    fields_desc = [ ByteEnumField('type', 0x03, _FRAME_TYPES),
                    FieldLenField('len', None, length_of='data', fmt='B'),
                    StrLenField('data', '', length_from=lambda pkt: pkt.len),
                    StrFixedLenField('sig', '', length=8),
                    XShortField('hash', None),
                    ]

# Payload Sub Packets
# ---------------------
class MessageSegment(Packet):
    name = 'message segment'
    fields_desc = [ ByteEnumField('type', None, _PLD_FRAME_TYPES),
                    FieldLenField('len', None, length_of='data', fmt='B'),
                    StrLenField('data', '', length_from=lambda p: p.len),
                    ]

    def extract_padding(self, pay):
        return "",pay

    registered_options = {}
    @classmethod
    def register_variant(cls):
        cls.registered_options[cls.type.default] = cls
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt:
            o = ord(_pkt[0])
            return cls.registered_options.get(o, cls)
        return cls

class Message(Packet):
    name = 'message'
    fields_desc = [ SaveRoomPacketListField('segments', [], MessageSegment, 2),
                    XShortField('hash', None)
                    ]

class EncryptedMessage(Packet):
    name = 'encrypted message'
    fields_desc = [ PacketListField('segments', [], MessageSegment, length_from=lambda pkt: 17),
                    ]

# TODO: Handle Encrypted Messages
class InitialsSegment(MessageSegment):
    name = 'initials'
    fields_desc = [ ByteEnumField('type', 0x03, _PLD_FRAME_TYPES),
                    FieldLenField('len', None, length_of='msg', fmt='B'),
                    StrLenField('initials', '', length_from=lambda pkt: pkt.len),
                    ]

class TextSegment(MessageSegment):
    name = 'message'
    fields_desc = [ ByteEnumField('type', 0x04, _PLD_FRAME_TYPES),
                    FieldLenField('len', None, length_of='msg', fmt='B'),
                    StrLenField('msg', '', length_from=lambda pkt: pkt.len),
                    ]

class LocationSegment(MessageSegment):
    name = 'location'
    fields_desc = [ ByteEnumField('type', 0x06, _PLD_FRAME_TYPES),
                    FieldLenField('len', None, length_of='location', fmt='B'),
                    PacketListField('location', [], MessageSegment, length_from=lambda pkt: pkt.len)
                    ]

class HighlightMsgSegment(MessageSegment):
    name = 'hilight msg'
    fields_desc = [ ByteEnumField('type', 0x07, _PLD_FRAME_TYPES),
                    FieldLenField('len', None, length_of='msg', fmt='B'),
                    StrLenField('msg', '', length_from=lambda pkt: pkt.len),
                    ]

class LatitudeSegment(MessageSegment):
    name = 'latitude'
    fields_desc = [ ByteEnumField('type', 0x08, _PLD_FRAME_TYPES),
                    XByteField('len', 0x08),
                    IEEEDoubleField('lat', None),
                    ]
class LongitudeSegment(MessageSegment):
    name = 'longitude'
    fields_desc = [ ByteEnumField('type', 0x09, _PLD_FRAME_TYPES),
                    XByteField('len', 0x08),
                    IEEEDoubleField('lon', None),
                    ]
class TimestampSegment(MessageSegment):
    name = 'ts'
    fields_desc = [ ByteEnumField('type', 0x13, _PLD_FRAME_TYPES),
                    XByteField('len', 0x04),
                    IntField('ts', None),
                    ]

class SourceSegment(MessageSegment):
    '''
    unk4, sep, and unk5 technically don't belong to this packet.
    It's a bit of a scapy-ism hack.
    '''
    name = 'src'
    fields_desc = [ ByteEnumField('type', 0xfb, _PLD_FRAME_TYPES),
                    XByteField('len', 0x0f),
                    XByteField('unk1', None),
                    XShortField('unk2', None),
                    GotennaGIDField('gid', ''),
                    XShortField('unk4', None),
                    XByteField('unk5', None),
                    XByteField('unk6', None),
                    ShortField('msg_ctr', None),
                    ]

class PubKeySegment(MessageSegment):
    name = 'pubkey rsp'
    fields_desc = [ ByteEnumField('type', 0xfc, _PLD_FRAME_TYPES),
                    FieldLenField('len', 0x31, length_of='pubkey', fmt='B'),
                    StrLenField('pubkey', '', length_from=lambda pkt: pkt.len),
                    ]

# Bindings
# ---------------------
bind_layers(Gotenna, Control, type=0x11)     # TX: Want to send a broadcast message
bind_layers(Gotenna, Control, type=0x10)     # TX: Want to send a DM
bind_layers(Gotenna, Control, type=0x62)     # RX: "Go ahead"

bind_layers(Gotenna, DataHeader, type=0x23) # TX: Here is who I am (just my name?)
bind_layers(Gotenna, DataHeader, type=0x34) # RX: Here is who I am (and my key)
bind_layers(Gotenna, DataHeader, type=0x45) # TX: Here is the data
bind_layers(Gotenna, DataHeader, type=0x56)     # RX: Message received

