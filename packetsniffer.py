import sys
import socket
import struct
import textwrap
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QTextEdit, QLineEdit, QMessageBox
from PyQt5.QtCore import QThread, pyqtSignal

class PacketSniffer:
    def __init__(self, target_ip):
        self.target_ip = target_ip
        self.conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    def sniff_packets(self, callback):
        try:
            while True:
                raw_data, addr = self.conn.recvfrom(65536)
                dest_mac, src_mac, eth_proto, data = self.ethernet_frame(raw_data)

                if eth_proto == 8:  # IPv4
                    (version, header_length, ttl, proto, src, target, data) = self.ipv4_packets(data)

                    # Check if the IP address matches
                    if src == self.target_ip or target == self.target_ip:
                        message = self.format_ethernet_info(dest_mac, src_mac, eth_proto, version, header_length, ttl, proto, src, target, data)
                        
                        if proto == 1:  # ICMP
                            message += self.handle_icmp(data)

                        elif proto == 6:  # TCP
                            message += self.handle_tcp(data)

                        elif proto == 17:  # UDP
                            message += self.handle_udp(data)

                        else:
                            message += '\t Data:\n' + self.format_multi_line('\t\t', data)

                        callback(message)
                else:
                    callback('Data:\n' + self.format_multi_line('\t', data))

        except KeyboardInterrupt:
            self.conn.close()

        except Exception as e:
            callback(f"[-] An error occurred: {e}")
            self.conn.close()

    # Unpack Ethernet frame
    def ethernet_frame(self, data):
        dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
        return self.get_mac_addr(dest_mac), self.get_mac_addr(src_mac), socket.htons(proto), data[14:]

    # Return properly formatted MAC address
    def get_mac_addr(self, bytes_addr):
        bytes_str = map('{:02x}'.format, bytes_addr)
        return ':'.join(bytes_str).upper()

    # Format multi-line data
    def format_multi_line(self, prefix, string, size=80):
        size -= len(prefix)
        if isinstance(string, bytes):
            string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
            if size % 2:
                size -= 1
        return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

    # Unpack IPv4 packet
    def ipv4_packets(self, data):
        version_header_length = data[0]
        version = version_header_length >> 4 
        header_length = (version_header_length & 15) * 4
        ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
        return version, header_length, ttl, proto, self.ipv4(src), self.ipv4(target), data[header_length:]

    # Return properly formatted IPv4 address
    def ipv4(self, addr):
        return '.'.join(map(str, addr))

    # Handle ICMP packets
    def handle_icmp(self, data):
        icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
        return f'\t ICMP packets:\n\t\t Type: {icmp_type}, Code: {code}, Checksum: {checksum}\n\t\t Data:\n' + self.format_multi_line('\t\t\t', data[4:])

    # Handle TCP packets
    def handle_tcp(self, data):
        (src_port, dest_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
        offset = (offset_reserved_flags >> 12) * 4
        flag_urg = (offset_reserved_flags & 32) >> 5
        flag_ack = (offset_reserved_flags & 16) >> 4
        flag_psh = (offset_reserved_flags & 8) >> 3
        flag_rst = (offset_reserved_flags & 4) >> 2
        flag_syn = (offset_reserved_flags & 2) >> 1
        flag_fin = offset_reserved_flags & 1 
        return f'\t TCP Segment:\n\t\t Source Port: {src_port}, Destination Port: {dest_port}\n\t\t Sequence: {sequence}, Acknowledgement: {acknowledgement}\n\t\t Flags:\n\t\t\t URG: {flag_urg}, ACK: {flag_ack}, PSH: {flag_psh}, RST: {flag_rst}, SYN: {flag_syn}, FIN: {flag_fin}\n\t\t DATA:\n' + self.format_multi_line('\t\t\t', data[offset:])

    # Handle UDP packets
    def handle_udp(self, data):
        src_port, dest_port, length = struct.unpack('! H H 2x H', data[:8])
        return f'\t UDP Segment:\n\t\t Source Port: {src_port}, Destination Port: {dest_port}, Length: {length}'

class SnifferThread(QThread):
    new_message = pyqtSignal(str)

    def __init__(self, target_ip):
        super().__init__()
        self.sniffer = PacketSniffer(target_ip)

    def run(self):
        self.sniffer.sniff_packets(self.new_message.emit)

class PacketSnifferApp(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("Packet Sniffer")
        self.setGeometry(100, 100, 800, 600)
        layout = QVBoxLayout()

        self.target_ip_input = QLineEdit(self)
        self.target_ip_input.setPlaceholderText("Enter the IP address to sniff packets for")
        layout.addWidget(self.target_ip_input)

        self.start_button = QPushButton("Start Sniffing", self)
        self.start_button.clicked.connect(self.start_sniffing)
        layout.addWidget(self.start_button)

        self.output_text = QTextEdit(self)
        self.output_text.setReadOnly(True)
        layout.addWidget(self.output_text)

        self.setLayout(layout)

    def start_sniffing(self):
        target_ip = self.target_ip_input.text()
        if not target_ip:
            QMessageBox.warning(self, "Input Error", "Please enter an IP address.")
            return

        self.sniffer_thread = SnifferThread(target_ip)
        self.sniffer_thread.new_message.connect(self.append_output)
        self.sniffer_thread.start()

    def append_output(self, message):
        self.output_text.append(message + "\n")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PacketSnifferApp()
    window.show()
    sys.exit(app.exec_())
