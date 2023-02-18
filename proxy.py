import sys
import socket
from threading import Lock, Thread, active_count

port, sub, attack = sys.argv[1:]

port = int(port)
sub = int(sub)
attack = int(attack)

ATTACKED_URL = b"""
HTTP/1.1 200 OK
Content-Type: text/html

<html><body><h1>You are being attacked</h1></body></html>
"""

BAD_URL = b"""
HTTP/1.1 400 Bad Request
Content-Type: text/html

<html><head><title>400 Bad Request</title></head><body><center><h1>400 Bad Request</h1></center><hr><center>nginx/1.18.0 (Ubuntu)</center></body></html>
"""

lock = Lock()

TELEMETRY_MAP = {}

def listen_and_process_client():
    try:
        client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_sock.bind(('', port))
        client_sock.settimeout(10)
        client_sock.listen()
        print("Successful Socket Initialization at [ %d ]" %(port))
    except Exception as e:
        print("Socket Initialization Failed")
        print(e)

    while True:
        try:
            client_conn, address = client_sock.accept()
            data = client_conn.recv(8192)

            # during attack mode, no need to progress any further
            if attack:
                lock.acquire()
                client_conn.send(ATTACKED_URL)
                client_conn.close()
                key = getTelemetryKey(data)
                TELEMETRY_MAP.setdefault(key, 0)
                TELEMETRY_MAP[key] += len(ATTACKED_URL)
                lock.release()
                continue

            thr = Thread(target=process, args=(client_conn, data))
            thr.start()
        except socket.timeout:
            if active_count() == 1 and TELEMETRY_MAP:
                for key, value in TELEMETRY_MAP.items():
                    print(f"{key}, {value}")
                TELEMETRY_MAP.clear()
            continue
        except KeyboardInterrupt:
            client_sock.close()
            sys.exit(1)

def process(client_conn, data):
    try:
        lines = data.split(b'\n')

        url_line = lines[0]
        url = url_line.split(b' ')[1]

        if not url_line.startswith(b'GET'):
            client_conn.send(BAD_URL)
            client_conn.close()
            return

        http_pos = url.find(b'://')
        if http_pos == -1:
            temp = url
        else:
            temp = url[(http_pos+3):]
        
        port_colon_pos = temp.find(b':')
        port_end_pos = temp.find(b'/')

        host = ''
        port = -1

        if port_colon_pos == -1 or port_end_pos < port_colon_pos:
            port = 80
            host = temp[:port_end_pos]
        else:
            port = int((temp[port_colon_pos+1:port_end_pos]))
            host = temp[:port_colon_pos]

        host = host.decode()

        send_server_and_reply_client(host, port, client_conn, data)

    except Exception as e:
        print(e)
        pass

def send_server_and_reply_client(host, port, client_conn, data):
    try:
        first_data_line = data.split(b'\n')[0]
        split_first_data_line = first_data_line.split(b' ')

        if sub and is_image(split_first_data_line[1]):
            split_first_data_line[1] = b'http://ocna0.d2.comp.nus.edu.sg:50000/change.jpg'
            first_data_line = b' '.join(split_first_data_line)
            data = data.replace(data.split(b'\n')[0], first_data_line)

        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.settimeout(5)
        server_sock.connect((host, port))
        server_sock.sendall(data)

        while True:
            reply = server_sock.recv(8192)
            if(len(reply) > 0):
                client_conn.send(reply)
            else:
                break

            if not reply.startswith(b"HTTP/1.0 200 OK") and not reply.startswith(b"HTTP/1.1 200 OK"):
                continue

            lock.acquire()
            key = getTelemetryKey(data)
            TELEMETRY_MAP.setdefault(key, 0)
            TELEMETRY_MAP[key] += getReplyContentLength(reply)
            lock.release()

        server_sock.close()
        client_conn.close()

    except socket.timeout:
        server_sock.close()
        client_conn.close()

def is_image(url):
    if url.endswith(b'.jpg') or url.endswith(b'.jpeg') or url.endswith(b'.png') or url.endswith(b'.gif'):
        return True
    return False

def getTelemetryKey(data):
    lines = data.split(b'\n')
    for line in lines:
        if line.startswith(b'Referer:'):
            return line.split(b' ')[1].decode().strip('\r')
    return lines[0].split(b' ')[1].decode().strip('\r')

def getReplyContentLength(reply):
    reply_lines = reply.split(b'\n')

    for line in reply_lines:
        if line.startswith(b'Content-Length:'):
            return int(line.split(b' ')[1])
    
    reply_split = reply.split(b"\r\n\r\n")
    return sys.getsizeof(reply_split[1]) if len(reply_split) > 1 else 0

if __name__ == "__main__":
    listen_and_process_client()