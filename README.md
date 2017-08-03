# GoTenna + Sauron

This GNU Radio Module passively monitors goTenna traffic with a Software
Defined Radio, logs raw packets to disk, and displays broadcast communication
traffic to the screen.

Encrypted traffic is also logged. If enough of the conversation is captured,
the "to", "from", and "length" fields are displayed.

You can download the slide deck for our presentation at the Wireless Village
[here](https://github.com/tkuester/slide_decks/raw/master/2017_Gotenna_RE.pdf).

[@bjt2n3904](https://twitter.com/bjt2n3904)
[@tb69rr](https://twitter.com/tb69rr)

## The Code

This is a bit hacked together right now! My apologies.

In the python folder, you will find two files. The easiest to talk about is
`scapy_gotenna.py`. There, you will find Scapy classes which detail the
structure of goTenna packets.

Each goTenna packet starts with a byte indicating the packet type, and a
sixteen byte long header. The header is interpreted differently for each
part of communication.

Some goTenna packets are extended by a frame, which follows a standard
**type**, **length**, **data**, **checksum** format.

`gotenna_sink.py` is the GNU Radio block responsible for intercepting,
structuring, and printing the captured packets to the screen. (It is currently
a horrendous mess.) It contains a finite state machine which tracks the
current state of the communication channel, in efforts to inform the user
what is happening.

The flow graph simply breaks the 4 MHz wide spectrum into the five channels,
and demodulates each one separately. Received packets are sent to the
goTenna sink, mentioned above.

Finally, `multiportrx.py` allows you to connect to and monitor multiple
serial ports simultaneously. This is useful for monitoring the debug
port on the goTenna.

## TODO: The things we haven't accomplished!

* Checksums!
* Crypto / Signing
* Transmitting
* Indication of signal quality
* Group Chat / Emergency Broadcast
* How the goTenna handles bad / corrupted packets
* More documentation!
* Sample packets and *.cfiles for analysis!

## Hardware Requirements

Your SDR needs to be able to listen to 150 MHz at 4 MSPS. For now, we have
tested this project with the HackRF and the Ettus B200. You will obviously
also need a goTenna to listen to communications!

This project does not (yet) work with RTL-SDRs, though it should soon!

## Installing

There are a few requirements to run this script. PyBombs is coming soon! Until
then, here is the manual process.

1. Install GNU Radio to your system via your favorite means. Don't forget to
   grab the development headers!
2. Install scapy
3. Install [gr-reveng](https://github.com/tkuester/gr-reveng)
4. Install [gr-nwr](https://github.com/awalls-cx18/gr-nwr) at revision `2cce7cfb`
5. Install gr-gotenna (this project)
6. Compile and run the flowgraph under `apps/gotenna_4msps.grc`

Remember, the standard method to install a GNU Radio module is:

1. cd gr-project
2. mkdir build && cd build
3. cmake ..
4. make -j8
5. sudo make install
6. sudo ldconfig

## Greetz
* awalls for helping us use his awesome clock recovery tools
