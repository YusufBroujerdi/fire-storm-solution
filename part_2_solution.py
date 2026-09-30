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



#To handle tracking whether recent bytes correspond to the substring CTFS.
class CtfsChecker:

    def __init__(self):
        self.last_four_bytes = b''

    #Returns whether last four bytes were CTFS. Also returns a byte to send
    #that we were keeping to see if it became part of a valid bytestring.
    def check_byte(self, byte):

        # print(f'self.last_four_bytes type: {type(self.last_four_bytes)} value: {self.last_four_bytes}')
        # print(f'byte parameter type: {type(byte)} value: {byte}')

        self.last_four_bytes += byte

        #if adding the new byte makes bytestring too long, we need to
        #return the oldest character for sending.
        if len(self.last_four_bytes) > 4:
            old_byte = self.last_four_bytes[0]
            self.last_four_bytes = self.last_four_bytes[1:]
        else:
            old_byte = None

        if self.last_four_bytes == b'CTFS':
            self.last_four_bytes = b''
            return True, old_byte
        else:
            return False, old_byte

    #I'll make sure leftover bytes are emptied before program ends
    def __del__(self):
        if self.last_four_bytes != b'':
            raise Exception("You need to empty ctfs_checker of bytes")



def deduce_sending_ports(byte_stream : SocketHandler):

    sending_ports = []

    #Get first byte of 6 byte destination mac address
    destination_mac_address = byte_stream.get_byte()
    #Get the other 5 bytes
    for i in range(0, 5):
        destination_mac_address += byte_stream.get_byte()

    #Get first byte of 6 byte source mac address
    source_mac_address = byte_stream.get_byte()
    #Get the other 5 bytes
    for i in range(0, 5):
        source_mac_address += byte_stream.get_byte()

    #If packet is going to a monitoring address, it should unconditionally
    #be sent to monitoring port in addition to usual ports
    if any(
        [destination_mac_address[:3] == address_start
        for address_start in monitoring_mac_address_starts]
    ):
        sending_ports.append(monitoring_port)

    #If traffic is not from a malicious address, we can send it to the usual ports.
    if all(
        [source_mac_address[:3] != address_start
        for address_start in malicious_mac_address_starts]
    ):
        #For the time being, I'll assume all traffic is tcp traffic
        sending_ports.append(tcp_port)

    #Before exiting function, send the bytes used to deduce ports.
    for sending_port in sending_ports:
        for byte in destination_mac_address + source_mac_address:
            byte_stream.send_byte(byte, sending_port)

    return sending_ports

    
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



def main():

    byte_stream = SocketHandler()
    ctfs_checker = CtfsChecker()
    byte = byte_stream.get_byte()
    pdf_fragments = dict()
    
    while byte is not None:

        packet_found, byte_to_send = ctfs_checker.check_byte(byte)

        if byte_to_send is not None:
            byte_stream.send_byte(byte_to_send)

        if packet_found:
            fragment = extract_packet(byte_stream)
            if fragment.file_id not in pdf_fragments.keys():
                pdf_fragments[fragment.file_id] = []
            pdf_fragments[fragment.file_id].append(fragment)

        byte = byte_stream.get_byte()

    #Make sure remaining bytes are sent
    for byte in ctfs_checker.last_four_bytes:
        byte_stream.send_byte(byte)
    ctfs_checker.last_four_bytes = b''

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
