import select
import socket
import sys
import os
import errno

DEFAULT_PIPE_FILE = '/tmp/strongswan.pipe'
DEFAULT_BACKLOG = 32
DEFAULT_RECV_BUFSIZE = 64

def get_response(data):
    parts = data.split(' ')
    if parts[0] == 'ACQUIRE':
        return '2a0a:4b00:1234::6'
    elif parts[0] == 'ATTR':
        return 'DNS6 2a0a:4b00:1234::1'
    elif parts[0] == 'RELEASE':
        return 'OKAY'

def main(pipe_file):
    if os.path.exists(pipe_file):
        os.remove(pipe_file)

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(pipe_file)
    server.listen(DEFAULT_BACKLOG)
    input = [server]

    while True:
        try:
            inputready, outputready, exceptready = select.select(input, [], [])

            for s in inputready:
                if s == server:
                    client, address = server.accept()
                    input.append(client)
                else:
                    data = ''
                    while True:
                        buf = s.recv(DEFAULT_RECV_BUFSIZE)
                        if buf:
                            data += buf
                            if data[-1] == '\n':
                                break
                        else:
                            s.close()
                            input.remove(s)
                            break
                    if data:
                        data = data.rstrip()
                        print('<- ' + data)

                        response = get_response(data)
                        print('-> ' + response)
                        s.send(response)
        except IOError, e:
            if e.errno not in [errno.EPIPE, errno.ECONNRESET]:
                raise e

    server.close()
    os.remove(pipe_file)

if __name__ == '__main__':
  pipe_file = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_PIPE_FILE
  main(pipe_file)
