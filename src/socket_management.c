#include <arpa/inet.h>
#include <errno.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include "../headers/socket_management.h"

//loopback IP translated into 4 byte integer (in network order)
#define LOOPBACK_IP inet_addr("127.0.0.1")

//Ports get written to network order in function body
#define RECV_PORT 5733
#define SEND_PORT 5744

//Since we expect only one client, 1 is a reasonable value.
//This can be adapted later if necessary.
#define LISTEN_BACKLOG 1

//common buffer size for sending / receiving bytes
#define BUFFER_SIZE 1024



struct RecvSocket initialize_receiving_socket() {

  unsigned char *buffer;
  char bind_check, listen_check;
  int socket_fd, client_fd;
  struct RecvSocket receiving_socket;

  //As part of the socket API, we specify a sockaddr_in for ipv4
  //addresses. This struct is later cast as the "polymorphic" sockaddr.
  struct sockaddr_in recv_address = {
    .sin_family  =  AF_INET,
    .sin_addr    =  {LOOPBACK_IP},
    .sin_port    =  htons(RECV_PORT),
    .sin_zero    =  {0}
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



struct SendSocket initialize_sending_socket_on_port(uint16_t port) {

  unsigned char *buffer;
  char connect_check;
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
    .sin_addr    =  {LOOPBACK_IP},
    .sin_port    =  htons(port),
    .sin_zero    =  {0}
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



struct SendSocket initialize_sending_socket() {
  return initialize_sending_socket_on_port(SEND_PORT);
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
  return (int) receiving_socket->buffer[receiving_socket->buffer_index++];
}



//Helper function for situations where the stream must not end.
//(like while reading a CTFS packet)
unsigned char get_non_EOF_byte(struct RecvSocket *receiving_socket) {

  int candidate_byte;

  if ((candidate_byte = get_byte(receiving_socket)) == EOF) {
    printf("Unexpected EOF while reading stream.\n");
    exit(-1);
  }
  return (unsigned char) candidate_byte;
}



void get_non_EOF_bytes(
  struct RecvSocket *receiving_socket,
  unsigned char *buffer,
  uint64_t length
) {
  for (uint64_t i = 0; i < length; i++)
    buffer[i] = get_non_EOF_byte(receiving_socket);
}



void send_byte(struct SendSocket *sending_socket, unsigned char byte_to_send) {

  unsigned char *starting_byte;
  int16_t bytes_sent, bytes_to_send;

  //If buffer is full, keep trying to send bytes until all are sent.
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
    sending_socket->buffer_index = 0;
  }

  //Add byte to send to buffer and increment buffer index.
  sending_socket->buffer[sending_socket->buffer_index++] = byte_to_send;
}




void send_byte_on_socket_list(struct SendSocketList *sockets, unsigned char byte) {

  struct SendSocketList *socket_list;

  for (socket_list = sockets; socket_list != NULL; socket_list = socket_list->next)
    send_byte(socket_list->socket, byte);
}



void send_byte_on_sockets(
  struct SendSocket *sockets[],
  unsigned char number_of_sockets,
  unsigned char byte
) {

  unsigned char i;

  for (i = 0; i < number_of_sockets; i++)
    send_byte(sockets[i], byte);
}



//Free buffer and close client/socket.
void cleanup_receiving_socket(struct RecvSocket *receiving_socket) {
  free(receiving_socket->buffer);
  close(receiving_socket->client_fd);
  close(receiving_socket->socket_fd);
}



//Send remaining bytes, in addition to freeing buffer and closing socket.
void cleanup_sending_socket(struct SendSocket *sending_socket) {

  unsigned char *starting_byte;
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
