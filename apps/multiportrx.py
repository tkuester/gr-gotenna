#!/usr/bin/python
import sys
import time
import serial
import threading
import logging

class SerialRdr(threading.Thread):
    def __init__(self, port, baud=115200):
        threading.Thread.__init__(self)
        self.port = port
        self.baud = baud
        self.stopped = threading.Event()

    def run(self):
        lgr = logging.getLogger(self.port)
        lgr.info("Starting")
        ser = None

        while not self.stopped.is_set():
            try:
                if ser is None:
                    ser = serial.Serial(self.port, self.baud, timeout=1)
                    lgr.info("Opened Serial port")

                line = ser.readline()
                if not line:
                    continue
                lgr.info('%.6f, %s, %s', time.time(), self.port, line.strip())
            except StandardError as e:
                lgr.info(e)
                if ser:
                    try:
                        self.ser.close()
                    except:
                        pass

                ser = None
                time.sleep(1)
                continue

        try:
            if ser:
                self.ser.close()
        except:
            pass

    def stop(self):
        self.stopped.set()

def main():
    if len(sys.argv) < 2:
        print >> sys.stderr, "Usage: %s tty0 [tty1, ...]" % sys.argv[0]
        print >> sys.stderr, "  Receives and interleaves lines from multiple serial ports"
        sys.exit(1)

    logging.basicConfig(stream=sys.stdout, level=logging.INFO)
    lgr = logging.getLogger()

    threads = []
    for argv in sys.argv[1:]:
        threads.append(SerialRdr(argv))
        threads[-1].start()

    try:
        while True:
            line = raw_input()
            lgr.info(line)
    except (KeyboardInterrupt, EOFError):
        pass

    for thr in threads:
        thr.stop()
        thr.join()

if __name__ == '__main__':
    main()

