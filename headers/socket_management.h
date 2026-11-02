#pragma once

#include <stdint.h>

//Struct to abstract away receiving data through socket
struct RecvSocket {
  int socket_fd;
  int client_fd;
  uint32_t buffer_index;
  uint32_t buffer_end_index;
  unsigned char *buffer;
};



//Struct to abstract away sending data through socket
struct SendSocket {
  unsigned char *buffer;
  int socket_fd;
  uint32_t buffer_index;
};



struct RecvSocket initialize_receiving_socket();
struct SendSocket initialize_sending_socket();
struct SendSocket initialize_sending_socket_on_port(uint16_t port);

int get_byte(struct RecvSocket *receiving_socket);
unsigned char get_non_EOF_byte(struct RecvSocket *receiving_socket);
void get_non_EOF_bytes(
  struct RecvSocket *receiving_socket,
  unsigned char *buffer,
  uint64_t length
);

void send_byte(struct SendSocket *sending_socket, unsigned char byte_to_send);
void send_byte_on_sockets(
  struct SendSocket *sockets[],
  unsigned char number_of_sockets,
  unsigned char byte
);

void cleanup_receiving_socket(struct RecvSocket *receiving_socket);
void cleanup_sending_socket(struct SendSocket *sending_socket);
