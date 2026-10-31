import socket
import threading
import struct
from concurrent.futures import ThreadPoolExecutor

executor = ThreadPoolExecutor(max_workers= 20)
port = 53
ip = '127.0.0.1'

def parse_dns_name(data, offset):
    labels =[]
    while True:
        length = data[offset]
        if length == 0:
            offset+=1
            break

        if (length & 0xC0) == 0xC0:
            pointer = struct.unpack('!H', data[offset : offset + 2])[0] & 0x3FFF
            sub_name, _ = parse_dns_name(data, pointer)
            labels.append(sub_name)
            offset += 2
            break

        else:
            offset += 1
            lable = data[offset: offset + length].decode('utf-8')
            labels.append(lable)
            offset += length
    return ".".join(labels), offset


def extract_next_ip(response_data):
    header = struct.unpack('!HHHHHH', response_data[:12])
    tx_id, flags, qdcount, ancount, nscount, arcount = header

    offset = 12
    for _ in range(qdcount):
        _, offset = parse_dns_name(response_data, offset)
        offset += 4

    def skip_or_read_record(current_offset):
        _, current_offset = parse_dns_name(response_data, current_offset)
        rtype, rclass, ttl, rdlength = struct.unpack('!HHLH', response_data[current_offset: current_offset + 10])
        current_offset += 10
        rdata = response_data[current_offset: current_offset + rdlength]
        current_offset += rdlength
        return rtype, rdata, current_offset

    for _ in range(ancount + nscount):
        _, _, offset = skip_or_read_record(offset)

    for _ in range(arcount):
        rtype, rdata, offset = skip_or_read_record(offset)
        if rtype == 1 and len(rdata) == 4:
            return f"{rdata[0]}.{rdata[1]}.{rdata[2]}.{rdata[3]}"

    return None


def resolve_iterative(original_data):
    current_target_ip = "199.7.83.42"
    resolver_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    resolver_sock.settimeout(3.0)

    for step in range(10):
        print(f"   [Итерация {step + 1}] Спрашиваем {current_target_ip}...")
        try:
            resolver_sock.sendto(original_data, (current_target_ip, 53))
            response_data, _ = resolver_sock.recvfrom(4096)

            header = struct.unpack('!HHHHHH', response_data[:12])
            tx_id, flags, qdcount, ancount, nscount, arcount = header

            rcode = flags & 0x000F
            if rcode == 3:
                print(f"   Домен не существует (NXDOMAIN). Возвращаем клиенту.")
                return response_data

            if ancount > 0:
                print(f"   Сервер {current_target_ip} прислал финальный ответ.")
                return response_data
            print(f"   Ищем следующий сервер. Authority: {nscount}, Additional: {arcount}")
            next_ip = extract_next_ip(response_data)

            if next_ip:
                print(f"   Нашли следующий сервер: {next_ip}")
                current_target_ip = next_ip
            else:
                print("   Тупик: в секции Additional нет нужных IP.")
                return response_data

        except socket.timeout:
            print(f"   Таймаут при ожидании от {current_target_ip}")
            return None
        except Exception as e:
            print(f"   Ошибка при резолве: {e}")
            return None

    return None

def multiply(qname):
    if ".multiply." in qname:
        prefix = qname.split(".multiply.")[0]
        parts = prefix.split(".")
        try:
            res = 1
            for i in parts:
                res = (res * int(i)) % 256
            return f"127.0.0.{res}"
        except ValueError:
            return None
    return None


def build_response(data, tx_id, next_offset, ip_str):
    flags = 0x8180
    header = struct.pack('!HHHHHH', tx_id, flags, 1, 1, 0, 0)
    question = data[12 : next_offset + 4]
    name_ptr = 0xC00C
    qtype = 1
    qclass = 1
    ttl = 300
    rdlength = 4

    ip_parts = [int(p) for p in ip_str.split('.')]
    rdata = struct.pack('!BBBB', ip_parts[0], ip_parts[1], ip_parts[2], ip_parts[3])

    answer = struct.pack('!HHHLH', name_ptr, qtype, qclass, ttl, rdlength) + rdata
    return header + question + answer

def send_response(response_bytes, addr, sock, protocol):
    if protocol == "UDP":
        sock.sendto(response_bytes, addr)
    elif protocol == "TCP":
        length_prefix = struct.pack('!H', len(response_bytes))
        sock.sendall(length_prefix + response_bytes)
def request(data, addr, sock, protocol):
    try:
        header = struct.unpack('!HHHHHH', data[:12])
        tx_id, flags, qdcount, ancount, nscount, arcount = header
        qname, next_offset = parse_dns_name(data, 12)
        qtype, qclass = struct.unpack('!HH', data[next_offset : next_offset + 4])
        print(f"[{protocol}] Клиент {addr} спрашивает ID:{tx_id} Имен: {qname} Тип: {qtype}")

        multiply_ip = multiply(qname)
        if multiply_ip and qtype == 1:
            print(f"-> Формируем ответ multiply: {multiply_ip}")
            resp = build_response(data, tx_id, next_offset, multiply_ip)
            send_response(resp, addr, sock, protocol)  # ИСПРАВЛЕНО
            return

        print(f"-> Запускаем итеративный поиск для {qname}")
        resolved_response = resolve_iterative(data)

        if resolved_response:
            send_response(resolved_response, addr, sock, protocol)
        else:
            print("-> Не удалось разрешить домен.")

    except Exception as e:
        print(f"Ошибка при разборе пакета: {e}")
    finally:
        if protocol == "TCP":
            try:
                sock.close()
            except Exception:
                pass

def udp():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((ip, port))
    print("UDP сервер слушает прот 53...")

    while True:
        data, addr = sock.recvfrom(512)
        executor.submit(request, data, addr, sock, "UDP")

def tcp():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((ip, port))
    sock.listen(5)
    print("TCP сервер слушает порт 53...")

    while True:
        conn, addr = sock.accept()
        length_bytes = conn.recv(2)
        if not length_bytes:
            conn.close()
            continue

        msg_len = struct.unpack('!H', length_bytes)[0]
        data = conn.recv(msg_len)
        executor.submit(request, data, addr, conn, "TCP")


if __name__ == "__main__":
    threading.Thread(target=udp, daemon=True).start()
    threading.Thread(target=tcp, daemon=True).start()

    try:
        import time

        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nСервер остановлен.")