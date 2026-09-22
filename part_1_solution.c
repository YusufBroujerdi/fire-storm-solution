#include <arpa/inet.h>
#include <errno.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>



//loopback IP translated into 4 byte integer (in network order)
#define LOOPBACK_IP inet_addr("127.0.0.1")
//Rewrite integer port in network order (big endian)
#define RECV_PORT htons(5733)
//Rewrite integer port in network order
#define SEND_PORT htons(5744)

//Since we expect only one client, 1 is a reasonable value.
//This can be adapted later if necessary.
#define LISTEN_BACKLOG 1

//common buffer size for sending / receiving bytes
#define BUFFER_SIZE 1024

//The 32 byte integer corresponding to CTFS ()


//Struct to abstract away receiving data through socket
struct RecvSocket {
  int socket_fd;
  int client_fd;
  uint32_t buffer_index;
  uint32_t buffer_end_index;
  char *buffer;
};



//Struct to abstract away sending data through socket
struct SendSocket {
  char *buffer;
  int socket_fd;
  uint32_t buffer_index;
};



//Struct will be helpful in reordering PDF packets later on
struct PdfFragment {
  char *payload;
  char *terminal_byte;
  uint16_t sequence_number;
};



//An interface for managing fragments and their payloads
struct PdfFragmentHandler {
  char *payload_storage;
  struct PdfFragment *fragments;
  uint64_t payload_storage_size;
  uint64_t fragments_size;
  uint64_t payload_storage_index;
  uint64_t fragment_index;
};



//Tracks recent bytes received so we can check for matches with "CTFS". Note
//the length member to track how many bytes are currently stored.
struct LastFourBytes {
  char bytes[4];
  char length;
};



//Returned by check_byte. Tells caller if last four bytes were ctfs AND
//if there is a byte that needs to be sent.
struct ByteCheckResult{
  int byte_to_send;
  char packet_found;
};



struct RecvSocket initialize_receiving_socket() {

  char bind_check, listen_check, *buffer;
  int socket_fd, client_fd;
  struct RecvSocket receiving_socket;

  //As part of the socket API, we specify a sockaddr_in for ipv4
  //addresses. This struct is later cast as the "polymorphic" sockaddr.
  struct sockaddr_in recv_address = {
    .sin_family  =  AF_INET,
    .sin_addr    =  LOOPBACK_IP,
    .sin_port    =  RECV_PORT,
    .sin_zero    =  0
  };

  //Specifies we want a tcp, ipv4 socket.
  socket_fd = socket(AF_INET, SOCK_STREAM, 0);

  //It seems sensible to terminate the program right away if any
  //calls fail. We expect the program to run in a particular
  //environment under particular conditions.
  if (socket_fd == -1) {
    printf("Socket call did not return valid file descriptor\n");
    exit(-1);
  }

  //Note we cast recv_address into the generic sockaddr for the bind.
  bind_check = bind (
    socket_fd,
    (struct sockaddr *) &recv_address,
    sizeof(struct sockaddr_in)
  );

  if (bind_check != 0) {
    printf("Address binding failed\n");
    exit(-1);
  }

  listen_check = listen(socket_fd, LISTEN_BACKLOG);

  if (listen_check != 0) {
    printf("Listening on port failed.\n");
    exit(-1);
  }

  client_fd = accept(socket_fd, NULL, NULL);

  if (client_fd == -1) {
    printf("Invalid client file descriptor returned.\n");
    exit(-1);
  }

  //This will need to be freed in the destructor.
  buffer = malloc(BUFFER_SIZE);
  if (buffer == NULL) {
    printf("allocating buffer for receiving data failed\n");
    exit(-1);
  }

  receiving_socket.buffer = buffer;
  receiving_socket.buffer_index = 0;
  receiving_socket.buffer_end_index = 0;
  receiving_socket.socket_fd = socket_fd;
  receiving_socket.client_fd = client_fd;

  return receiving_socket;
}



struct SendSocket initialize_sending_socket() {

  char connect_check, *buffer;
  int socket_fd;
  struct timespec start_time, current_time, tenth_second;
  struct SendSocket sending_socket;
  
  socket_fd = socket(AF_INET, SOCK_STREAM, 0);

  if (socket_fd == -1) {
    printf("(Sending) Socket call did not return valid file descriptor\n");
    exit(-1);
  }

  struct sockaddr_in send_address = {
    .sin_family  =  AF_INET,
    .sin_addr    =  LOOPBACK_IP,
    .sin_port    =  SEND_PORT,
    .sin_zero    =  0
  };

  //Below call should never error with valid clock id, according to man page
  clock_gettime(CLOCK_MONOTONIC, &start_time);

  //The test code creates the client socket before the server socket,
  //which means we may need to attempt to connect to the server several times
  //before a connection is successfully made.
  while (1) {

    connect_check = connect(
      socket_fd,
      (struct sockaddr *) &send_address,
      sizeof(struct sockaddr_in)
    );

    //If loop doesn't break here, connect_check must be -1 and connection failed.
    if (connect_check == 0)
      break;

    //connect() should only fail because the connection was refused
    //i.e. the server has not been started yet.
    if (errno != ECONNREFUSED) {
      printf("Connecting socket failed for a reason besides refused connection\n");
      exit(-1);
    }

    //If the connection is still failing after 5s, the connection
    //has been refused for too long and the program should timeout.
    clock_gettime(CLOCK_MONOTONIC, &current_time);
    if (current_time.tv_sec - start_time.tv_sec >= 5
        && current_time.tv_nsec >= start_time.tv_nsec) {
      printf("Connecting socket has failed to connect to server for too long\n");
      exit(-1);
    }

    //Try again after 0.1 secs
    tenth_second.tv_sec = 0;
    tenth_second.tv_nsec = 100000000;
    nanosleep(&tenth_second, NULL);
  }

  //This will need to be freed in the destructor.
  buffer = malloc(BUFFER_SIZE);
  if (buffer == NULL) {
    printf("allocating buffer for sending data failed\n");
    exit(-1);
  }

  sending_socket.socket_fd = socket_fd;
  sending_socket.buffer = buffer;
  sending_socket.buffer_index = 0;

  return sending_socket;
}



//Returns an int rather than a char so we can safely return EOF.
int get_byte(struct RecvSocket *receiving_socket) {

  int bytes_received;

  //If buffer has been fully read, perform a new read to get more bytes.
  if (receiving_socket->buffer_index == receiving_socket->buffer_end_index) {

    bytes_received = read(
      receiving_socket->client_fd,
      receiving_socket->buffer,
      BUFFER_SIZE
    );

    if (bytes_received == -1) {
      printf("Failed to receive bytes via receiving socket.\n");
      exit(-1);
    }
    else if (bytes_received == 0) 
      return EOF;
    else
      //Set buffer_end_index to the number of bytes received in read call.
      receiving_socket->buffer_end_index = bytes_received;

    receiving_socket->buffer_index = 0;
  }

  //Return char from reading buffer and increment buffer index.
  return receiving_socket->buffer[receiving_socket->buffer_index++];
}



//Helper function for situations where the stream must not end.
//(like while reading a CTFS packet)
char get_non_EOF_byte(struct RecvSocket *receiving_socket) {

  int candidate_byte;

  if ((candidate_byte = get_byte(receiving_socket)) == EOF) {
    printf("Unexpected EOF while reading stream.\n");
    exit(-1);
  }
  return (char) candidate_byte;
}



void send_byte(struct SendSocket *sending_socket, char byte_to_send) {

  char *starting_byte;
  int16_t bytes_sent, bytes_to_send;

  //If buffer is full, keep trying to send chars until all are sent.
  //Mimics python's "sendall" method. May have performance cost?
  if (sending_socket->buffer_index == BUFFER_SIZE) {
    starting_byte = sending_socket->buffer;
    //loop breaks when bytes_to_send is 0, which is tracked via the write call.
    for(bytes_to_send = BUFFER_SIZE; bytes_to_send > 0;) {
      bytes_sent = write(sending_socket->socket_fd, starting_byte, bytes_to_send);
      if (bytes_sent == -1) {
        printf("Writing to sending socket failed.\n");
        exit(-1);
      }
      //Recalculate number of bytes left to send and where they start.
      bytes_to_send -= bytes_sent;
      starting_byte += bytes_sent;
    }
  }

  //Add byte to send to buffer and increment buffer index.
  sending_socket->buffer[sending_socket->buffer_index++] = byte_to_send;
}



//Free buffer and close client/socket.
void cleanup_receiving_socket(struct RecvSocket *receiving_socket) {
  free(receiving_socket->buffer);
  close(receiving_socket->client_fd);
  close(receiving_socket->socket_fd);
}



//Send remaining bytes, in addition to freeing buffer and closing socket.
void cleanup_sending_socket(struct SendSocket *sending_socket) {

  char *starting_byte;
  int16_t bytes_sent, bytes_to_send;

  starting_byte = sending_socket->buffer;
  for(bytes_to_send = sending_socket->buffer_index; bytes_to_send > 0;) {
    bytes_sent = write(sending_socket->socket_fd, starting_byte, bytes_to_send);
    if (bytes_sent == -1) {
      printf("Writing to sending socket failed.\n");
      exit(-1);
    }
    bytes_to_send -= bytes_sent;
    starting_byte += bytes_sent;
  }

  free(sending_socket->buffer);
  close(sending_socket->socket_fd);
}



struct PdfFragmentHandler initialize_fragment_handler() {

  char *payload_storage;
  struct PdfFragment *fragments;
  uint64_t payload_storage_size, fragments_size;

  //32MiB seems reasonable for a pdf. But we will make provisions for
  //extending the payload if necessary. Same for the fragments.
  payload_storage_size = 32 * (1 << 10) * (1 << 10);
  payload_storage = malloc(payload_storage_size);
  if (payload_storage == NULL) {
    printf("allocating storage for pdf fragments failed\n");
    exit(-1);
  }

  //256 fragments seems like a reasonable soft bound.
  fragments_size = 256 * sizeof(struct PdfFragment); 
  fragments = malloc(fragments_size);
  if (fragments == NULL) {
    printf("allocating storage for pdf fragments failed\n");
    exit(-1);
  }

  struct PdfFragmentHandler handler = {
    .payload_storage = payload_storage,
    .payload_storage_index = 0,
    .payload_storage_size = payload_storage_size,
    .fragments = fragments,
    .fragment_index = 0,
    .fragments_size = fragments_size
  };

  return handler;
}



void extend_payload_storage(struct PdfFragmentHandler *fragment_handler) {

  char *new_payload_storage;
  
  new_payload_storage = realloc(
    fragment_handler->payload_storage,
    fragment_handler->payload_storage_size * 2
  );
  if (new_payload_storage == NULL) {
    printf("Attempt to extend payload storage failed.\n");
    exit(-1);
  }

  fragment_handler->payload_storage = new_payload_storage;
}



void extend_fragments_storage(struct PdfFragmentHandler *fragment_handler) {

  struct PdfFragment *new_fragments_storage;
  
  new_fragments_storage = realloc(
    fragment_handler->fragments,
    fragment_handler->fragments_size * 2
  );
  if (new_fragments_storage == NULL) {
    printf("Attempt to extend fragment storage failed.\n");
    exit(-1);
  }

  fragment_handler->fragments = new_fragments_storage;
}



void cleanup_fragment_handler(struct PdfFragmentHandler *fragment_handler) {
  free(fragment_handler->fragments);
  free(fragment_handler->payload_storage);
}



//sorts fragments by sequence number, via the quicksort algorithm.
void quicksort_fragments(
  struct PdfFragment *fragments,
  uint32_t length
) {

  char comparison;
  uint32_t pivot_index, last_index, next_low, length_of_low, length_of_high;
  struct PdfFragment tmp, *address_of_high;

  if (length == 0) {
    printf("This function should never be called on length 0");
    exit(-1);
  }

  //Since this algorithm is recursive, a base case is needed to ensure recursion
  //terminates at the leaves
  if (length == 1) {
    return;
  }

  //Harmless helper variable
  last_index = length - 1;

  //Assign a random fragment to be the pivot
  pivot_index = rand() % length;
  //Move the pivot to the end to simplify iteration
  tmp = fragments[pivot_index];
  fragments[pivot_index] = fragments[last_index];
  fragments[last_index] = tmp;

  //Rearrange fragments with those lower than index together on the left
  //so those fragments higher will end up together on the right.
  next_low = 0;
  for (uint32_t i; i < last_index; i++) {
    //Ensure i is placed on the low side if less than pivot
    if (fragments[i].sequence_number < fragments[last_index].sequence_number) {
      //Switch fragment in next available low slot with i
      tmp = fragments[i];
      fragments[i] = fragments[next_low];
      fragments[next_low] = tmp;
      //increment next_low to get a new available low slot.
      next_low++;
    }
  }

  //Put the pivot between the block of fragments lower than the pivot and the
  //block of fragments higher than the pivot. We can use next_low for this.
  tmp = fragments[last_index];
  fragments[last_index] = fragments[next_low];
  fragments[next_low] = tmp;

  //length_of_high is (total length) - (length of the low) - (1 for the pivot)
  length_of_low = next_low;
  length_of_high = length - length_of_low - 1;
  //Starting address of high is just the memory address after the pivot.
  address_of_high = fragments + next_low + 1;

  //Recursively call the function on both the low block and high block.
  //This will complete the algorithm via divide and conquer.
  quicksort_fragments(fragments, length_of_low);
  quicksort_fragments(address_of_high, length_of_high);
}



void assemble_pdf_from_fragments(struct PdfFragmentHandler *fragment_handler) {

  FILE *file;
  struct PdfFragment *fragment;
  char * byte;

  //Sort fragments by sequence number.
  quicksort_fragments(
    fragment_handler->fragments,
    fragment_handler->fragment_index
  );

  file = fopen("decoded_file.pdf", "w");
  if (file == NULL) {
    printf("Failed to open file to put pdf.\n");
    exit(-1);
  }

  //For each fragment, for each char in fragment payload, put char in file.
  for(
    fragment = fragment_handler->fragments;
    fragment < fragment_handler->fragments + fragment_handler->fragment_index;
    fragment++
  ) {
    for(byte = fragment->payload; byte != fragment->terminal_byte; byte++) {
      if (fputc(*byte, file) == EOF) {
        printf("Failed to write char to file.\n");
        exit(-1);
      }
    }
  }
}



void initialize_last_four_bytes(struct LastFourBytes *last_four_bytes) {
  last_four_bytes->length = 0;
}



//Given a received byte, deduces whether last four bytes were CTFS and if a byte
//needs to be sent through the send socket.
struct ByteCheckResult check_byte(struct LastFourBytes *last_four_bytes, char byte) {

  char length;
  struct ByteCheckResult result;

  //If there's already four bytes, the first byte must be sent and space must
  //be made for the new byte. Either way, new byte is appended to last_four_bytes.
  if (last_four_bytes->length == 4) {
    result.byte_to_send = last_four_bytes->bytes[0];
    memmove(last_four_bytes->bytes, last_four_bytes->bytes + 1, 3);
    last_four_bytes->bytes[3] = byte;
  }
  else {
    result.byte_to_send = EOF;
    last_four_bytes->bytes[last_four_bytes->length++] = byte;
  }

  if (
    last_four_bytes->length == 4
    && memcmp(last_four_bytes->bytes, "CTFS", 4) == 0
  ) {
    result.packet_found = 1;
    last_four_bytes->length = 0;
  }
  else
    result.packet_found = 0;

  return result;
}



//Extract payload of CTFS packet, supposing "CTFS" has just been read.
void extract_packet(
  struct PdfFragmentHandler *handler,
  struct RecvSocket *byte_stream
) {

  char sequence_byte[2], length_byte[2], next_byte;
  uint16_t sequence_number, length;
  struct PdfFragment *new_fragment;

  if (handler->fragment_index == handler->fragments_size)
    extend_fragments_storage(handler);

  //Read the sequence and length bytes from stream.
  sequence_byte[0] = get_non_EOF_byte(byte_stream);
  sequence_byte[1] = get_non_EOF_byte(byte_stream);
  length_byte[0] = get_non_EOF_byte(byte_stream);
  length_byte[1] = get_non_EOF_byte(byte_stream);

  //Extracting length and sequence number this way is endian-agnostic. Though
  //assuming network is big endian and host is little endian also seems reasonable.
  sequence_number = ntohs(*((uint16_t *) sequence_byte));
  length = ntohs(*((uint16_t *) length_byte));

  //The header file is 16 bytes, including the "CTFS". Discard other header bytes
  for (uint8_t i = 0; i < 8; i++)
    get_non_EOF_byte(byte_stream);

  new_fragment = handler->fragments + handler->fragment_index++;
  new_fragment->sequence_number = sequence_number;
  new_fragment->payload = handler->payload_storage + handler->payload_storage_index;
  new_fragment->terminal_byte = new_fragment->payload + length;

  for (uint16_t n = 0; n < length; n++) {

    //If payload storage is about to run out of memory, extend it.
    if (handler->payload_storage_size - handler->payload_storage_index < 10)
      extend_payload_storage(handler);

    next_byte = get_non_EOF_byte(byte_stream);
    handler->payload_storage[handler->payload_storage_index++] = next_byte;
  }
}



void get_pdf_file() {

  struct RecvSocket receiving_socket;
  struct SendSocket sending_socket;
  struct PdfFragmentHandler fragment_handler;
  struct ByteCheckResult byte_check_result;
  struct LastFourBytes last_four_bytes;
  int byte, counter = 0;

  receiving_socket = initialize_receiving_socket();
  sending_socket = initialize_sending_socket();
  fragment_handler = initialize_fragment_handler();

  printf("Byte successfully read!\n");

  while (byte != EOF) {

    counter++;

    byte_check_result = check_byte(&last_four_bytes, byte);

    if (byte_check_result.byte_to_send != EOF)
      send_byte(&sending_socket, (char) byte_check_result.byte_to_send);

    if (byte_check_result.packet_found)
      extract_packet(&fragment_handler, &receiving_socket);

    byte = get_byte(&receiving_socket);
  }

  for (char index = 0; index < last_four_bytes.length; index++) {
    send_byte(&sending_socket, last_four_bytes.bytes[index]);
  }

  assemble_pdf_from_fragments(&fragment_handler);

  cleanup_sending_socket(&sending_socket);
  cleanup_receiving_socket(&receiving_socket);
  cleanup_fragment_handler(&fragment_handler);
}



int main() {
  get_pdf_file();
  return 0;
}
