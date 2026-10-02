import socket
import time


malicious_mac_address_starts = (
    b'\x00\x0C\x29',
    b'\x00\x50\x56',
    b'\x00\x1C\x14'
)

monitoring_mac_address_starts = (
    b'\x00\x1A\xA0',
    b'\x00\x1E\xC9',
    b'\x00\x15\x5D'
)

monitoring_port = 5745
tcp_port = 5744
udp_port = 5746

ethernet_header_length = 14

#value corresponding to tcp/udp in protocol field of ipv4 header
tcp = 0x06
udp = 0x11

byte_counter = 0

#Class to hold information about individual sending socket
class SendSocket:
    def __init__(self, socket_send):
        self.object = socket_send
        self.buffer = bytearray()

#Class to abstract away reading and writing to sockets.
class SocketHandler:

    #Initialize receiving and sending sockets, as well as buffers.
    def __init__(self, ip = '127.0.0.1', recv_port = 5733, send_ports = [5744, 5745, 5746]):

        #initialize receiving socket
        self._socket_recv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket_recv.bind((ip, recv_port))
        self._socket_recv.listen()
        self._client_recv, _ = self._socket_recv.accept()
        self._socket_send = dict()

        #initialize sending socket
        for send_port in send_ports:

            self._socket_send[send_port] = SendSocket(
                socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            )
            sending_socket = self._socket_send[send_port]

            timeout_start = time.time()
            while True:
                time.sleep(0.1)
                try:
                    sending_socket.object.connect((ip, send_port))
                    break
                except ConnectionRefusedError:
                    if time.time() - timeout_start > 5:
                        raise Exception("Timeout while connecting to client socket")

        #initialize receiving buffers
        self._buffer_recv = b''
        self._buffer_recv_index = 1

    #Return next byte from stream, or None if stream is finished
    def get_byte(self):

        global byte_counter
        byte_counter += 1

        #Get a new buffer if current one has been fully read.
        if self._buffer_recv_index >= len(self._buffer_recv):
            self._buffer_recv = self._client_recv.recv(1024)
            self._buffer_recv_index = 0

        #If buffer is still empty at this stage, stream must be finished.
        if len(self._buffer_recv) == 0:
            return None

        #The below line is necessary due to how indexing bytestrings in python works.
        valid_index = slice(self._buffer_recv_index, self._buffer_recv_index + 1)
        #Return a byte and increment index.
        byte = self._buffer_recv[valid_index]
        self._buffer_recv_index += 1
        return byte

    def send_byte(self, byte, send_port):

        #get relevant sending socket for port
        sending_socket = self._socket_send[send_port]

        #Send buffer if current one is full.
        if len(sending_socket.buffer) >= 1024:
            sending_socket.object.sendall(bytes(sending_socket.buffer))
            sending_socket.buffer = bytearray()

        sending_socket.buffer.append(byte)

    def send_byte_on_ports(self, byte, send_ports):

        for send_port in send_ports:
            self.send_byte(byte, send_port)

    #Perform socket cleanup
    def __del__(self):

        #Make sure remaining bytes are sent from all buffers when program ends.
        for sending_socket in self._socket_send.values():
            if len(sending_socket.buffer) > 0:
                sending_socket.object.sendall(bytes(sending_socket.buffer))
            sending_socket.object.close()

        self._client_recv.close()
        self._socket_recv.close()
        


#Wrapper object for pdf fragments and their sequence number  
class PdfStringFragment:

    def __init__(self, sequence_number, payload, file_id):
        self.sequence_number = sequence_number
        self.payload = payload
        self.file_id = file_id

    #Magic methods will simplify ordering the fragments.
    def __lt__(self, other):
        return self.sequence_number < other.sequence_number

    def __gt__(self, other):
        return self.sequence_number > other.sequence_number

    
    
#returns a CTFS packet, having confirmed the previous four bytes were a
#valid CTFS string.
def extract_packet(byte_stream : SocketHandler):

    #The first header is the sequence number - 2 bytes.
    sequence_bytes = byte_stream.get_byte()
    sequence_bytes += byte_stream.get_byte()
    sequence_number = int.from_bytes(sequence_bytes, 'big')

    #The second header is the length number - 2 bytes.
    length_bytes = byte_stream.get_byte()
    length_bytes += byte_stream.get_byte()
    length = int.from_bytes(length_bytes, 'big')

    #File id
    file_id_byte = byte_stream.get_byte()
    file_id = int.from_bytes(file_id_byte, 'big')

    #Header including CTFS string is 16 bytes. Discard the remaining 8 bytes.
    for i in range(0, 7):
        byte_stream.get_byte()

    #We can use the length number to find the pdf payload.
    payload = bytearray()
    for i in range(0, length):
        byte = int.from_bytes(byte_stream.get_byte(), 'big')
        payload.append(byte)

    return PdfStringFragment(sequence_number, bytes(payload), file_id)



def validate_ip_packet(bytes):

    ehl = ethernet_header_length

    conditions = [
        bytes[ehl - 2: ehl] == b'\x08\x00', #ethertype should be 0x0800 for ipv4
        bytes[ehl] & 0xf0 == 0x40, #first 4 bits should be 4, for ipv4
        bytes[ehl] & 0x0f == 0x05, #next 4 bits represent header length, assuming it's 5*32 bits
    ]

    for condition_index in range(len(conditions)):
        if not conditions[condition_index]:
            num = int.from_bytes(bytes, 'big')
            raise Exception(f'Packet is not CTFS and fails condition {condition_index} for being an ethernet/ipv4 packet')


def send_ip_packet(header, byte_stream : SocketHandler):

    ehl = ethernet_header_length

    #Compute bytes to send besides header. Note the ipv4 length includes the header.
    ipv4_packet_length = int.from_bytes(header[ehl + 2: ehl + 4], 'big')
    length_excluding_headers = ipv4_packet_length - 20

    protocol = header[ehl + 9]

    #Find mac addresses, for determining sending ports
    destination_mac_address = header[:6]
    source_mac_address = header[6:12]
    sending_ports = []

    if destination_mac_address[:3] in monitoring_mac_address_starts:
        sending_ports.append(monitoring_port)

    if source_mac_address[:3] not in malicious_mac_address_starts:
        if protocol == tcp:
            sending_ports.append(tcp_port)
        elif protocol == udp:
            sending_ports.append(udp_port)

    for byte in header:
        #Note this call simply does nothing if sending_ports is empty
        byte_stream.send_byte_on_ports(byte, sending_ports)

    for i in range(length_excluding_headers):
        byte = int.from_bytes(byte_stream.get_byte(), 'big')
        byte_stream.send_byte_on_ports(byte, sending_ports)


def main():

    byte_stream = SocketHandler()
    pdf_fragments = dict()

    while True:

        first_packet_byte = byte_stream.get_byte()
        if first_packet_byte is None:
            break

        first_four_bytes = first_packet_byte
        for i in range(3):
            first_four_bytes += byte_stream.get_byte()

        if first_four_bytes == b'CTFS':
            fragment = extract_packet(byte_stream)
            if fragment.file_id not in pdf_fragments.keys():
                pdf_fragments[fragment.file_id] = []
            pdf_fragments[fragment.file_id].append(fragment)
            continue

        first_34_bytes = first_four_bytes
        for i in range(30):
            first_34_bytes += byte_stream.get_byte()

        validate_ip_packet(first_34_bytes)
        send_ip_packet(first_34_bytes, byte_stream)

    #sort by sequence number, using magic method in PdfStringFragment class
    for file_fragments in pdf_fragments.values():
        file_fragments.sort()

    #write ordered PdfStringFragment payloads to file
    for file_id, file_fragments in pdf_fragments.items():
        with open(f'{file_id}.pdf', 'wb') as pdf_file:
            for fragment in file_fragments:
                pdf_file.write(fragment.payload)


if __name__ == '__main__':

    main()
