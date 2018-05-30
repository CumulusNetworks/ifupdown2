#!/usr/bin/python
#
# Copyright 2016 Cumulus Networks, Inc. All rights reserved.
# Author: Julien Fortin, julien@cumulusnetworks.com
#
#

import os
import re
import sys
import json
import errno
import struct
import select
import socket
import signal

try:
    import ifupdown2.ifupdown.config as core_config
    from ifupdown2.ifupdown.log import log
    from ifupdown2 import __version__

    core_config.__version__ = __version__
except:
    import ifupdown.config as core_config
    from ifupdown.log import log

    core_config.__version__ = __import__('__init__').__version__


class Ifupdown2Complete(Exception):
    def __init__(self, status):
        self.status = status


class Ifupdown2Client:
    def __init__(self, argv):

        self.stdin = None
        self.argv = argv
        self.data = ''
        self.HEADER_SIZE = 4
        self.daemon_pid = -1

        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            self.socket.connect('/var/run/ifupdown2d/uds')

            signal.signal(signal.SIGINT, self.signal_handler)
            signal.signal(signal.SIGTERM, self.signal_handler)
            signal.signal(signal.SIGQUIT, self.signal_handler)

            try:
                self.SO_PEERCRED = socket.SO_PEERCRED
            except AttributeError:
                # powerpc is the only non-generic we care about. alpha, mips,
                # sparc, and parisc also have non-generic values.
                machine = os.uname()[4]
                if re.search(r'^(ppc|powerpc)', machine):
                    self.SO_PASSCRED = 20
                    self.SO_PEERCRED = 21
                else:
                    self.SO_PASSCRED = 16
                    self.SO_PEERCRED = 17
            try:
                self.socket.setsockopt(socket.SOL_SOCKET, self.SO_PASSCRED, 1)
            except Exception as e:
                raise Exception('setsockopt: %s' % str(e))

        except socket.error:
            self.socket.close()
            self.socket = None
            sys.stderr.write("""
    ERROR: %s could not connect to ifupdown2d

    Try starting ifupdown2d with:
    sudo systemctl start ifupdown2d

    To configure ifupdown2d to start when the box boots:
    sudo systemctl enable ifupdown2d
    """ % argv[0])

    def __del__(self):
        if self.socket:
            self.socket.close()

    def signal_handler(self, sig, frame):
        if self.daemon_pid > 0:
            os.kill(self.daemon_pid, sig)

    def read_data(self):
        ready = select.select([self.socket], [], [])
        if ready and ready[0] and ready[0][0] == self.socket:
            d = self.socket.recv(65536)
            if self.data:
                self.data += d
            else:
                self.data = d
            return True
        return False

    def get_packets(self):
        """
            ifupdown2 output is divided into "json packets"
            the first 4 bytes is the size of the next json
            object to etract

        """
        data_size = len(self.data)
        if not data_size:
            raise Ifupdown2Complete(status=1)

        packets = []
        try:
            while data_size > 0:
                packet_len = struct.unpack('=I', self.data[:self.HEADER_SIZE])[0]
                packet_data = self.data[self.HEADER_SIZE:packet_len + self.HEADER_SIZE]

                fmt = "=%ds" % packet_len

                packets.append(json.loads(struct.unpack(fmt, packet_data)[0]))

                self.data = self.data[self.HEADER_SIZE + packet_len:]
                data_size -= self.HEADER_SIZE + packet_len
        except:
            pass
        return packets

    def process_packets(self, packets):
        for packet in packets:
            if 'pid' in packet:
                self.daemon_pid = packet['pid']
            if 'stdout' in packet:
                sys.stdout.write(packet['stdout'])
            if 'stderr' in packet:
                sys.stderr.write(packet['stderr'])
            if 'status' in packet:
                raise Ifupdown2Complete(packet['status'])

    def run(self):
        status = 1
        if self.socket:
            for arg in ['-i', '--interfaces']:
                try:
                    if self.argv[self.argv.index(arg) + 1] == '-':
                        self.stdin = sys.stdin.read()
                        continue
                except (ValueError, IndexError):
                    pass

            self.socket.send(json.dumps({
                'argv': self.argv,
                'stdin': self.stdin
            }))

            try:
                while True:
                    try:
                        self.read_data()
                        self.process_packets(self.get_packets())
                    except Ifupdown2Complete as e:
                        status = e.status
                        break
                    except Exception as e:
                        if ((isinstance(e.args, tuple) and e[0] == 4)
                            or (hasattr(e, 'errno') and e.errno == errno.EINTR)):
                            pass
                        else:
                            raise
            except Exception as e:
                sys.stderr.write(str(e))
            finally:
                self.socket.close()
        return status if status != None else 1


def ifupdown2_standalone():
    try:
        import ifupdown2.ifupdown.main as main_ifupdown2
    except:
        import ifupdown.main as main_ifupdown2
    ifupdown2 = main_ifupdown2.Ifupdown2(daemon=False, uid=os.geteuid())
    ifupdown2.parse_argv(sys.argv)
    ifupdown2.update_logger()
    return ifupdown2.main()


def main():
    try:
        if 'use_daemon=yes' in open(core_config.IFUPDOWN2_CONF_PATH).read():
            return Ifupdown2Client(sys.argv).run()
        else:
            return ifupdown2_standalone()
    except KeyboardInterrupt:
        return 1
    except Exception as e:
        log.error(str(e))
        return 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(1)
