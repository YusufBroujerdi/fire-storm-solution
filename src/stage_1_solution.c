#include <arpa/inet.h>
#include <errno.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "../headers/socket_management.h"
#include "../headers/ctfs_packet_handling.h"




//Tracks recent bytes received so we can check for matches with "CTFS". Note
//the length member to track how many bytes are currently stored.
struct LastFourBytes {
  unsigned char bytes[4];
  unsigned char length;
};



//Returned by check_byte. Tells caller if last four bytes were ctfs AND
//if there is a byte that needs to be sent.
struct ByteCheckResult{
  int byte_to_send;
  char packet_found;
};



struct LastFourBytes initialize_last_four_bytes() {
  struct LastFourBytes last_four_bytes;
  memset(&last_four_bytes, 0, sizeof(last_four_bytes));
  return last_four_bytes;
}



//Given a received byte, deduces whether last four bytes were CTFS and if a byte
//needs to be sent through the send socket.
struct ByteCheckResult check_byte(
  struct LastFourBytes *last_four_bytes,
  unsigned char byte
) {

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



void get_pdf_file() {

  struct RecvSocket receiving_socket;
  struct SendSocket sending_socket;
  struct PdfFileIdHandler file_id_handler;
  struct ByteCheckResult byte_check_result;
  struct LastFourBytes last_four_bytes;
  int byte;

  receiving_socket = initialize_receiving_socket();
  sending_socket = initialize_sending_socket();
  file_id_handler = initialize_file_id_handler(100);
  last_four_bytes = initialize_last_four_bytes();

  byte = get_byte(&receiving_socket);

  while (byte != EOF) {

    byte_check_result = check_byte(&last_four_bytes, byte);

    if (byte_check_result.byte_to_send != EOF)
      send_byte(&sending_socket, (unsigned char) byte_check_result.byte_to_send);

    if (byte_check_result.packet_found)
      extract_ctfs_packet(&file_id_handler, &receiving_socket);

    byte = get_byte(&receiving_socket);
  }

  for (unsigned char index = 0; index < last_four_bytes.length; index++) {
    send_byte(&sending_socket, last_four_bytes.bytes[index]);
  }

  assemble_pdf_from_fragments(&file_id_handler);

  cleanup_sending_socket(&sending_socket);
  cleanup_receiving_socket(&receiving_socket);
  cleanup_file_id_handler(&file_id_handler);
}



int main() {
  get_pdf_file();
  return 0;
}
