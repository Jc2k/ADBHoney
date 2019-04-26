#!/usr/bin/env python

import asyncio
import hashlib
import os
import protocol
import socket
import struct
import sys
import threading
import time
import datetime
import binascii
import json
from argparse import ArgumentParser

__VERSION__ = '1.00'

MAX_READ_COUNT = 4096 * 4096
# sleep 1 second after each empty packets, wait 1 hour in total
MAX_EMPTY_PACKETS = 360
DEVICE_ID = 'device::http://ro.product.name =starltexx;ro.product.model=SM-G960F;ro.product.device=starlte;features=cmd,stat_v2,shell_v2'

class Logger:

    def __init__(self):
        self.listeners = []

    def publish(self, event):
        for subscriber in list(self.listeners):
            subscriber.put_nowait(event)

    async def listen(self):
        bus = asyncio.Queue()
        self.listeners.append(bus)
        try:
            while True:
                event = async bus.get()
                yield event
        finally:
            self.listeners.pop(bus, None)


async def log(CONFIG, logger):
    async for event in logger.listen():
        message = event['message']
        if CONFIG['logfile'] is None:
            print(message)
            sys.stdout.flush()
        else:
            with open(CONFIG['logfile'], 'a') as f:
                print(message, file=f)


async def jsonlog(CONFIG, logger):
    with open(CONFIG['json_log'], 'a') as fp:
        async for event in logger.listen():
            json.dump(obj, fp)
            fp.flush()


async def hpfeeds(CONFIG, logger):
    from hpfeeds.asyncio import ClientService

    async with ClientService() as service:
        for event in logger.listen():
            service.publish(
                'adbhoney',
                event,
            )


def getutctime():
    return datetime.datetime.utcnow().isoformat() + 'Z'


def dump_file_data(log, addr, real_fname, data, session, CONFIG):
    shasum = hashlib.sha256(data).hexdigest()
    fname = 'data-{}.raw'.format(shasum)
    if CONFIG['download_dir'] and not os.path.exists(CONFIG['download_dir']):
        os.makedirs(CONFIG['download_dir'])
    fullname = os.path.join(CONFIG['download_dir'], fname)
    log.publish({
        'eventid': 'adbhoney.session.file_upload',
        'timestamp': getutctime(),
        'unixtime': int(time.time()),
        'session': session,
        'message': 'Downloaded file with SHA-256 {} to {}'.format(shasum, fullname),
        'src_ip': addr[0],
        'shasum': shasum,
        'outfile': fullname,
        'sensor': CONFIG['sensor']
    })
    if not os.path.exists(fullname):
        with open(fullname, 'wb') as f:
            f.write(data)


def send_message(writer, command, arg0, arg1, data, CONFIG):
    newmessage = protocol.AdbMessage(command, arg0, arg1, data)
    if CONFIG['debug']:
        print('>>>>{}'.format(newmessage))
    writer.write(newmessage.encode())


def send_twice(writer, command, arg0, arg1, data, CONFIG):
    send_message(writer, command, arg0, arg1, data, CONFIG)
    send_message(writer, command, arg0, arg1, data, CONFIG)


def process_logging(comm_q, config):
    while True:
        obj_to_log = comm_q.get(True)
        if type(obj_to_log) is dict:
                jsonlog(obj_to_log, config)
        elif type(obj_to_log) is str:
                log(obj_to_log, config)
        elif type(obj_to_log) is tuple:
                dump_file_data(*obj_to_log)


async def process_connection(reader, writer, CONFIG, logger):
    start = time.time()
    session = binascii.hexlify(os.urandom(6))

    dest_ip, dest_port = writer.get_extra_info('sockname')
    src_ip, src_port = writer.get_extra_info('peername')

    logger.publish({
        'eventid': 'adbhoney.session.connect',
        'timestamp': getutctime(),
        'unixtime': int(start),
        'session': session,
        'message': 'New connection: {}:{} ({}:{}) [session: {}]'.format(addr[0], addr[1], localip, CONFIG['port'], session),
        'src_ip': addr[0],
        'src_port': addr[1],
        'dst_ip': localip,
        'dst_port': CONFIG['port'],
        'sensor': CONFIG['sensor']
    })

    states = []
    sending_binary = False
    dropped_file = ''
    empty_packets = 0
    filename = 'unknown'
    closedmessage = 'Connection closed'
    while True:
        debug_content = bytes()
        try:
            command = await reader.read(4)
            if not command:
                empty_packets += 1
                if empty_packets > MAX_EMPTY_PACKETS:
                    break
                # wait for more data
                time.sleep(1)
                continue
            empty_packets = 0
            debug_content += command
            arg1 = await reader.read(4)
            debug_content += arg1
            arg2 = await reader.read(4)
            debug_content += arg2
            data_length_raw = await reader.read(4)
            debug_content += data_length_raw
            data_length = struct.unpack('<L', data_length_raw)[0]
            data_crc = await reader.read(4)
            magic = await reader.read(4)
            data_content = bytes()

            if data_length > 0:
                # prevent reading the same stuff over and over again from some other attackers and locking the honeypot
                # max 1 byte read 64*4096 times (max packet length for ADB)
                read_count = 0

                while len(data_content) < data_length and read_count < MAX_READ_COUNT:
                    read_count += 1
                    # don't overread the content of the next data packet
                    bytes_to_read = data_length - len(data_content)
                    data_content += await reader.read(bytes_to_read)
            # check integrity of read data
            if len(data_content) < data_length:
                # corrupt content, abort the connection (probably not an ADB client)
                break
            # assemble a full data packet as per ADB specs
            data = command + arg1 + arg2 + data_length_raw + data_crc + magic + data_content
        except Exception as ex:
            closedmessage = 'Connection reset by peer'
            logger.publish({
                'eventid': 'adbhoney.session.exception',
                'timestamp': getutctime(),
                'unixtime': int(start),
                'session': session,
                'message': '{}\t{}\t {} : {}'.format(getutctime(), addr[0], repr(ex), repr(debug_content)),
                'src_ip': addr[0],
                'src_port': addr[1],
                'dst_ip': localip,
                'dst_port': CONFIG['port'],
                'sensor': CONFIG['sensor']
            })
            break

        try:
            message = protocol.AdbMessage.decode(data)[0]
            if CONFIG['debug']:
                # print message
                string = str(message)
                if len(string) > 96:
                    print('<<<<{} ...... {}'.format(string[0:64], string[-32:]))
                else:
                    print('<<<<{}'.format(string))
        except:
            # don't print anything, a lot of garbage coming in usually, just drop the connection
            break

        # keep a record of all the previous states in order to handle some weird cases
        states.append(message.command)

        # corner case for binary sending
        if sending_binary:
            # look for that shitty DATAXXXX where XXXX is the length of the data block that's about to be sent
            # (i.e. DATA\x00\x00\x01\x00)
            if message.command == protocol.CMD_WRTE and 'DATA' in message.data:
                data_index = message.data.index('DATA')
                payload_fragment = message.data[:data_index] + message.data[data_index + 8:]
                dropped_file += payload_fragment
            elif message.command == protocol.CMD_WRTE:
                dropped_file += message.data

            # truncate
            if 'DONE' in message.data:
                dropped_file = dropped_file[:-8]
                sending_binary = False
                dump_file_data(logger, addr, filename, dropped_file, session, CONFIG)
                # ADB has a shitty state machine, sometimes we need to send duplicate messages
                send_twice(writer, protocol.CMD_WRTE, 2, message.arg0, 'OKAY', CONFIG)
                #send_message(writer, protocol.CMD_WRTE, 2, message.arg0, 'OKAY', CONFIG)
                send_twice(writer, protocol.CMD_OKAY, 2, message.arg0, '', CONFIG)
                #send_message(writer, protocol.CMD_OKAY, 2, message.arg0, '', CONFIG)
                continue

            if message.command != protocol.CMD_WRTE:
                dropped_file += data

            send_twice(writer, protocol.CMD_OKAY, 2, message.arg0, '', CONFIG)
            #send_message(writer, protocol.CMD_OKAY, 2, message.arg0, '', CONFIG)

        else:   # regular flow
            # look for the data header that is first sent when initiating a data connection
            '''  /sdcard/stuff/exfiltrator-network-io.PNG,33206DATA '''
            if 'DATA' in message.data[:128]:
                sending_binary = True
                dropped_file = ''
                # if the message is really short, wrap it up
                if 'DONE' in message.data[-8:]:
                    sending_binary = False
                    predata = message.data.split('DATA')[0]
                    if predata:
                        filename = predata.split(',')[0]

                    dropped_file = message.data.split('DATA')[1][4:-8]
                    send_twice(writer, protocol.CMD_WRTE, 2, message.arg0, 'OKAY', CONFIG)
                    send_twice(writer, protocol.CMD_OKAY, 2, message.arg0, '', CONFIG)

                    dump_file_data(logger, addr, filename, dropped_file, session, CONFIG)
                    continue

                else:
                    predata = message.data.split('DATA')[0]
                    if predata:
                        filename = predata.split(',')[0]
                    dropped_file = message.data.split('DATA')[1][4:]

                send_twice(writer, protocol.CMD_OKAY, 2, message.arg0, '', CONFIG)
                continue

            if len(states) >= 2 and states[-2:] == [protocol.CMD_WRTE, protocol.CMD_WRTE]:
                # last block of messages before the big block of data
                filename = message.data
                send_message(writer, protocol.CMD_OKAY, 2, message.arg0, '', CONFIG)
                # why do I have to send the command twice??? science damn it!
                send_twice(writer, protocol.CMD_WRTE, 2, message.arg0, 'STAT\x07\x00\x00\x00', CONFIG)
            elif len(states) > 2 and states[-2:] == [protocol.CMD_OKAY, protocol.CMD_WRTE]:
                send_message(writer, protocol.CMD_OKAY, 2, message.arg0, '', CONFIG)
                # send_message(writer, protocol.CMD_WRTE, 2, message.arg0, 'FAIL', CONFIG)
            elif len(states) > 1 and states[-2:] == [protocol.CMD_OPEN, protocol.CMD_WRTE]:
                send_message(writer, protocol.CMD_OKAY, 2, message.arg0, '', CONFIG)
                if len(message.data) > 8:
                    send_twice(writer, protocol.CMD_WRTE, 2, message.arg0, 'STAT\x01\x00\x00\x00', CONFIG)
                    filename = message.data[8:]
            elif states[-1] == protocol.CMD_OPEN and 'shell' in message.data:
                send_message(writer, protocol.CMD_OKAY, 2, message.arg0, '', CONFIG)
                # change the WRTE contents with whatever you'd like to send to the attacker
                send_message(writer, protocol.CMD_WRTE, 2, message.arg0, '', CONFIG)
                send_message(writer, protocol.CMD_CLSE, 2, message.arg0, '', CONFIG)
                # print the shell command that was sent
                # also remove trailing \00
                logger.publish({
                    'eventid': 'adbhoney.command.input',
                    'timestamp': getutctime(),
                    'unixtime': int(time.time()),
                    'session': session,
                    'message': message.data[:-1],
                    'src_ip': addr[0],
                    'input': message.data[6:-1],
                    'sensor': CONFIG['sensor']
                })
            elif states[-1] == protocol.CMD_CNXN:
                send_message(writer, protocol.CMD_CNXN, 0x01000000, 4096, DEVICE_ID, CONFIG)
            elif states[-1] == protocol.CMD_OPEN and 'sync' not in message.data:
                send_message(writer, protocol.CMD_OKAY, 2, message.arg0, '', CONFIG)
            elif states[-1] == protocol.CMD_OPEN:
                send_message(writer, protocol.CMD_OKAY, 2, message.arg0, '', CONFIG)
            elif states[-1] == protocol.CMD_CLSE and not sending_binary:
                send_message(writer, protocol.CMD_CLSE, 2, message.arg0, '', CONFIG)
            elif states[-1] == protocol.CMD_WRTE and 'QUIT' in message.data:
                send_message(writer, protocol.CMD_OKAY, 2, message.arg0, '', CONFIG)
                send_message(writer, protocol.CMD_CLSE, 2, message.arg0, '', CONFIG)

        await writer.drain()

    duration = time.time() - start

    logger.publish({
        'eventid': 'adbhoney.session.closed',
        'timestamp': getutctime(),
        'unixtime': int(time.time()),
        'session': session,
        'message': '{} after {} seconds'.format(closedmessage, int(round(duration))),
        'src_ip': addr[0],
        'duration': duration,
        'sensor': CONFIG['sensor']
    })

    writer.close()


async def main_connection_loop(CONFIG):
    logger = Logger()

    tasks = []
    tasks.append(asyncio.create_task(
        log(CONFIG, logger)
    ))

    if args.json_log:
        tasks.append(asyncio.create_task(
            jsonlog(CONFIG, logger)
        ))

    if False:
        tasks.append(asyncio.create_task(
            hpfeeds(CONFIG, logger),
        ))

    bind_addr = CONFIG['addr']
    bind_port = CONFIG['port']
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    """ Set TCP keepalive on an open socket.

        It activates after 1 second (after_idle_sec) of idleness,
        then sends a keepalive ping once every 1 seconds (interval_sec),
        and closes the connection after 100 failed ping (max_fails)
    """
    s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    # pylint: disable=no-member
    if hasattr(socket, 'TCP_KEEPIDLE'):
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 1)
    elif hasattr(socket, 'TCP_KEEPALIVE'):
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPALIVE, 1)
    if hasattr(socket, 'TCP_KEEPINTVL'):
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 1)
    if hasattr(socket, 'TCP_KEEPCNT'):
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 100)
    # pylint: enable=no-member
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, True)
    s.bind((bind_addr, bind_port))
    s.listen(1)
    log('Listening on {}:{}.'.format(bind_addr, bind_port), CONFIG)
    server = await asyncio.start_server(
        lambda reader, writer: process_connection(CONFIG, reader, writer),
        sock=s,
    )
    tasks.append(server.serve_forever())

    await asyncio.gather(*tasks, return_exceptions=True)

if __name__ == '__main__':
    CONFIG = {}

    # Eventually these will be filled from a config file
    CONFIG['addr'] = '0.0.0.0'
    CONFIG['port'] = 5555
    CONFIG['download_dir'] = ''
    CONFIG['logfile'] = None
    CONFIG['json_log'] = None
    CONFIG['sensor'] = socket.gethostname()
    CONFIG['debug'] = False

    parser = ArgumentParser(version='%(prog)s version ' + __VERSION__, description='ADB Honeypot')

    parser.add_argument('-a', '--addr', type=str, default=CONFIG['addr'], help='Address to bind to (default: {})'.format(CONFIG['addr']))
    parser.add_argument('-p', '--port', type=int, default=CONFIG['port'], help='Port to listen on (default: {})'.format(CONFIG['port']))
    parser.add_argument('-d', '--dlfolder', type=str, default='', help='Directory for the uploaded samples (default: current)')
    parser.add_argument('-l', '--logfile', type=str, default=None, help='Log file (default: stdout')
    parser.add_argument('-j', '--jsonlog', type=str, default=None, help='JSON log file')
    parser.add_argument('-s', '--sensor', type=str, default=CONFIG['sensor'], help='Sensor name (default: {})'.format(CONFIG['sensor']))
    parser.add_argument('--debug', action='store_true', help='Produce verbose output')

    args = parser.parse_args()

    CONFIG['addr'] = args.addr
    CONFIG['port'] = args.port
    CONFIG['download_dir'] = args.dlfolder
    CONFIG['logfile'] = args.logfile
    CONFIG['json_log'] = args.jsonlog
    CONFIG['sensor'] = args.sensor
    CONFIG['debug'] = args.debug

    asyncio.run(main_connection_loop(CONFIG))
