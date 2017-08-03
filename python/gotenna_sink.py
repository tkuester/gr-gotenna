#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
# Copyright 2017 <+YOU OR YOUR COMPANY+>.
# 
# This is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3, or (at your option)
# any later version.
# 
# This software is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this software; see the file COPYING.  If not, write to
# the Free Software Foundation, Inc., 51 Franklin Street,
# Boston, MA 02110-1301, USA.
# 

import sys
import time
import traceback
from datetime import datetime
import random
from collections import OrderedDict

import scapy
import numpy

from gnuradio import gr
import pmt
import threading

from . import scapy_gotenna

STATE_IDLE = 0
STATE_DM_HANDSHAKE = 1
STATE_DM_DATA = 2
STATE_DM_COMPLETE = 3
STATE_BCAST = 4

class PacketNommer(object):
    def __init__(self, name):
        self.name = name
        self.reset_state()

    def reset_state(self):
        # TODO: try to use convo_id to keep packets together
        self.buff = OrderedDict()
        self.state = STATE_IDLE
        self.last_ts = None
        self.last_seq = 0
        self.enc = False
        self.tx_gid = None
        self.tx_initials = None
        self.rx_gid = None
        self.coord = None
        self.rx_hash16 = None
        self.tx_pubkey = None
        self.rx_pubkey = None
        self.msg = None
        self.msglen = None

    def poke(self, ts):
        if self.last_ts and (ts - self.last_ts) > 5:
            self.dump_buff()

    def nom_packet(self, ts, pkt):
        if pkt.type == 0x11: # bcast syn
            if self.state != STATE_IDLE:
                self.dump_buff()

            self.state = STATE_BCAST
            self.last_ts = ts
        elif pkt.type == 0x10: # DM syn
            if self.state != STATE_IDLE:
                self.dump_buff()

            self.state = STATE_DM_HANDSHAKE
            self.rx_hash16 = pkt.hash16
            self.last_ts = ts
        elif pkt.type == 0x62: # dm synack
            if self.state not in [STATE_IDLE, STATE_DM_HANDSHAKE]:
                self.dump_buff()

            self.state = STATE_DM_HANDSHAKE
            self.rx_hash16 = pkt.hash16_2
            self.last_ts = ts
        elif pkt.type == 0x23: # dm ident
            if self.state != STATE_DM_HANDSHAKE:
                self.dump_buff()

            if scapy_gotenna.IdentFrame in pkt:
                self.rx_gid = pkt.frame.gid
        elif pkt.type == 0x34: # dm ident ack, pubkey
            if self.state != STATE_DM_HANDSHAKE:
                self.dump_buff()

            if scapy_gotenna.KeyExchangeFrame in pkt:
                self.rx_pubkey = pkt.frame.pubkey

            self.state = STATE_DM_DATA
            self.last_ts = ts
        elif pkt.type == 0x45: # data packet (bcast and non-bcast)
            if self.state in [STATE_IDLE, STATE_BCAST] and (pkt.flags & 0x02 != 0):
                self.state = STATE_BCAST
                self.enc = False
                self.last_ts = ts
                self.buff[pkt.seq] = str(pkt.frame.data)

                # Check for out of order packets... fail for now
                if (pkt.seq == self.last_seq + 1):
                    self.last_seq = pkt.seq
                else:
                    self.dump_buff()

                # Hey, let's check if we have a whole packet right here
                try:
                    pkt = scapy_gotenna.Message(''.join(self.buff.values()))
                    if pkt.hash is not None:
                        self.dump_buff()
                        return
                except scapy.error:
                    pass

            elif self.state == STATE_DM_DATA and pkt.seq == (self.last_seq + 1):
                self.enc = True
                self.last_seq = pkt.seq
                self.buff[pkt.seq] = str(pkt.frame.data)
                self.last_ts = ts
            else:
                self.dump_buff()
        elif pkt.type == 0x56: # msg_ack
            # TODO: Check for "nah, not complete"
            self.state = STATE_DM_COMPLETE
            self.last_ts = ts
            self.dump_buff()

    def dump_buff(self):
        pld = ''.join(self.buff.values())
        pld_len = len(pld)

        try:
            if self.enc:
                pld = scapy_gotenna.EncryptedMessage(pld)
            else:
                pld = scapy_gotenna.Message(pld)
        except scapy.error:
            print >> sys.stderr, 'Bad message:', pld.encode('hex')
            self.reset_state()
            return

        for seg in pld.segments:
            if scapy_gotenna.PubKeySegment in seg:
                self.tx_pubkey = seg.pubkey
            elif scapy_gotenna.InitialsSegment in seg:
                self.tx_initials = seg.initials
            elif scapy_gotenna.SourceSegment in seg:
                self.tx_gid = seg.gid
            elif scapy_gotenna.LocationSegment in seg:
                lat = lon = loc_ts = 0
                loc_msg = None

                for loc in seg.location:
                    if scapy_gotenna.LatitudeSegment in loc:
                        lat = loc.lat
                    elif scapy_gotenna.LongitudeSegment in loc:
                        lon = loc.lon
                    elif scapy_gotenna.TimestampSegment in loc:
                        loc_ts = datetime.fromtimestamp(loc.ts - random.random() * 600)
                        loc_ts = loc_ts.isoformat()
                    elif scapy_gotenna.HighlightMsgSegment in loc and not self.enc:
                        loc_msg = loc.msg

                lat += random.random() * 0.01 - 0.005
                lon += random.random() * 0.01 - 0.005

                self.coord = (lat, lon, loc_ts, loc_msg)
            elif scapy_gotenna.TextSegment in seg and not self.enc:
                self.msg = seg.msg

        if self.state == STATE_BCAST:
            who = '%s / %s -> bcast' % (self.tx_gid, self.tx_initials)
        else:
            who = '%s -> %s' % (self.tx_gid, self.rx_gid)

        if self.state == STATE_BCAST:
            if self.msg:
                print '%s: %s' % (who, self.msg)
            if self.coord:
                (lat, lon, loc_ts, msg) = self.coord
                print '%s: %s {(%.3f, %.3f) @ %s}' % (who, msg, lat, lon, loc_ts)
        elif self.enc:
            text_len = pld_len - 28
            print '%s: Encrypted (potential len: %d)' % (who, text_len)

        if self.tx_gid and self.tx_pubkey:
            print self.tx_gid, 'pubkey:', self.tx_pubkey.encode('hex')
        if self.rx_gid and self.rx_pubkey:
            print self.tx_gid, 'pubkey:', self.rx_pubkey.encode('hex')

        self.reset_state()

class gotenna_sink(gr.basic_block):
    """
    docstring for block gotenna_sink
    """
    def __init__(self, sauron=True):
        gr.basic_block.__init__(self,
            name="gotenna_sink",
            in_sig=None,
            out_sig=None)

        self.sauron = sauron

        self.message_port_register_in(pmt.intern('pdus'))
        self.set_msg_handler(pmt.intern('pdus'), self.handle_pdu)

        self.channels = {
            'ch0': PacketNommer('ch0'),
            'ch1': PacketNommer('ch1'),
            'ch2': PacketNommer('ch2'),
            'ch3': PacketNommer('ch3')}

        self.stopped = threading.Event()
        self.thr = threading.Thread(target=self.poke_all)
        self.thr.start()

        print

    def stop(self):
        try:
            self.stopped.set()
        except StandardError:
            return

        try:
            self.thr.join(timeout=10)
        except StandardError:
            return

    def handle_pdu(self, pdu):
        if not pmt.is_pair(pdu):
            return

        meta = pmt.to_python(pmt.car(pdu)) or {}
        data = pmt.to_python(pmt.cdr(pdu))
        if meta.get('packed', False):
            bytez = str(bytearray(data))
        else:
            bytez = numpy.packbits(bytearray(data))

        ch_num = meta.get('name')
        ts = meta.get('ts')

        try:
            pkt = scapy_gotenna.Gotenna(bytez)
        except scapy.error:
            print >> sys.stderr, 'Bad packet:', bytez.encode('hex')
            return

        try:
            if ch_num == 'ch4' and pkt.type in [0x10, 0x11]:
                self.channels.get('ch%d' % pkt.next_chan).nom_packet(ts, pkt)
            else:
                self.channels.get(ch_num).nom_packet(ts, pkt)
        except StandardError as e:
            print >> sys.stderr, 'Failed calling nom_packet'
            print >> sys.stderr, 'Bad packet:', bytez.encode('hex')
            print >> sys.stderr, traceback.format_exc(e)

    def poke_all(self):
        while not self.stopped.wait(1.5):
            try:
                for ch in self.channels.values():
                    ch.poke(time.time())
            except StandardError as e:
                print >> sys.stderr, 'Failed calling poke on %s' % ch
                print >> sys.stderr, traceback.format_exc(e)


