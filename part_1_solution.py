import socket
import time



#Class to abstract away reading and writing to sockets.
class SocketHandler:

    #Initialize receiving and sending sockets, as well as buffers.
    def __init__(self, ip = '127.0.0.1', recv_port = 5733, send_port = 5744):

        #initialize receiving socket
        self._socket_recv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket_recv.bind((ip, recv_port))
        self._socket_recv.listen()
        self._client_recv, _ = self._socket_recv.accept()

        #initialize sending socket
        self._socket_send = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        timeout_start = time.time()
        while True:
            time.sleep(0.1)
            try:
                self._socket_send.connect((ip, send_port))
                break
            except ConnectionRefusedError:
                if time.time() - timeout_start > 5:
                    raise Exception("Timeout while connecting to client socket")

        #initialize_buffers
        self._buffer_send = bytearray()
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

    def send_byte(self, byte):

        #Send buffer if current one is full.
        if len(self._buffer_send) >= 1024:
            self._socket_send.sendall(bytes(self._buffer_send))
            self._buffer_send = bytearray()

        self._buffer_send.append(byte)

    #Perform socket cleanup
    def __del__(self):

        #Make sure remaining bytes are sent from buffer when program ends.
        if len(self._buffer_send) > 0:
            self._socket_send.sendall(bytes(self._buffer_send))

        self._client_recv.close()
        self._socket_recv.close()
        self._socket_send.close()
        


#Wrapper object for pdf fragments and their sequence number  
class PdfStringFragment:

    def __init__(self, sequence_number, payload):
        self.sequence_number = sequence_number
        self.payload = payload

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

    #Header including CTFS string is 16 bytes. Discard the remaining 8 bytes.
    for i in range(0, 8):
        byte_stream.get_byte()

    #We can use the length number to find the pdf payload.
    payload = bytearray()
    for i in range(0, length):
        byte = int.from_bytes(byte_stream.get_byte(), 'big')
        payload.append(byte)

    return PdfStringFragment(sequence_number, bytes(payload))



def main():

    byte_stream = SocketHandler()
    ctfs_checker = CtfsChecker()
    byte = byte_stream.get_byte()
    pdf_fragments = []
    
    while byte is not None:

        packet_found, byte_to_send = ctfs_checker.check_byte(byte)

        if byte_to_send is not None:
            byte_stream.send_byte(byte_to_send)

        if packet_found:
            pdf_fragments.append(extract_packet(byte_stream))

        byte = byte_stream.get_byte()

    #Make sure remaining bytes are sent
    for byte in ctfs_checker.last_four_bytes:
        byte_stream.send_byte(byte)
    ctfs_checker.last_four_bytes = b''

    #sort by sequence number, using magic method in PdfStringFragment class
    pdf_fragments.sort()

    #write ordered PdfStringFragment payloads to file
    with open('test.pdf', 'wb') as pdf_file:
        for fragment in pdf_fragments:
            pdf_file.write(fragment.payload)



if __name__ == '__main__':

    main()
