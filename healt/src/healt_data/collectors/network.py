import time
import psutil

last_net_sent = 0
last_net_recv = 0
last_disk_read = 0
last_disk_write = 0
last_time = time.time()


def get_network_and_disk_speed():
    global last_net_sent, last_net_recv, last_disk_read, last_disk_write, last_time
    current_time = time.time()
    elapsed = current_time - last_time
    if elapsed <= 0:
        elapsed = 1.0

    net = psutil.net_io_counters()
    disk = psutil.disk_io_counters()

    net_sent_speed = max(0.0, ((net.bytes_sent - last_net_sent) / elapsed) / 1024) if net else 0.0
    net_recv_speed = max(0.0, ((net.bytes_recv - last_net_recv) / elapsed) / 1024) if net else 0.0
    disk_read_speed = max(0.0, ((disk.read_bytes - last_disk_read) / elapsed) / (1024 * 1024)) if disk else 0.0
    disk_write_speed = max(0.0, ((disk.write_bytes - last_disk_write) / elapsed) / (1024 * 1024)) if disk else 0.0

    if net:
        last_net_sent = net.bytes_sent
        last_net_recv = net.bytes_recv
    if disk:
        last_disk_read = disk.read_bytes
        last_disk_write = disk.write_bytes
    last_time = current_time

    return net_sent_speed, net_recv_speed, disk_read_speed, disk_write_speed


def get_open_listening_ports():
    ports = set()
    try:
        for conn in psutil.net_connections(kind='tcp'):
            if conn.status == 'LISTEN' and conn.laddr:
                ports.add(conn.laddr.port)
    except Exception:
        pass
    return sorted(list(ports))
