#include <arpa/inet.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../headers/socket_management.h"
#include "../headers/stage_2_ctfs_packet_handling.h"

#define IPV4_HEADER_LENGTH 20
#define ETHERNET_HEADER_LENGTH 14
#define COMBINED_HEADER_LENGTH 34
#define MONITORING_PORT 5745
#define TCP_PORT 5744
#define UDP_PORT 5746
#define MONITORING_SOCKET_INDEX 0
#define TCP_SOCKET_INDEX 1
#define UDP_SOCKET_INDEX 2
#define TCP_PROTOCOL_VALUE 0x06
#define UDP_PROTOCOL_VALUE 0x11

const unsigned char malicious_mac_address_starts[3][3] = {
  {0x00, 0x0C, 0x29},
  {0x00, 0x50, 0x56},
  {0x00, 0x1C, 0x14}
};

const unsigned char monitoring_mac_address_starts[3][3] = {
  {0x00, 0x1A, 0xA0},
  {0x00, 0x1E, 0xC9},
  {0x00, 0x15, 0x5D}
};



//This function ensures our assumptions about the ip packet are true.
//It would make debugging easier if our program fails on future cases.
void validate_ip_packet(unsigned char *header) {

  unsigned char ehl;

  ehl = ETHERNET_HEADER_LENGTH;

  if (ntohs(* (uint16_t *) &header[ehl - 2]) != 0x0800) {
    printf("Error. Ethernet header's ethertype should always be 0x0800, indicating ipv4.");
    exit(-1);
  }

  if ((header[ehl] & 0xf0) != 0x40) {
    printf("Error. First four bits of ipv4 header should be 4, indicating ipv4.");
    exit(-1);
  }

  if ((header[ehl] & 0x0f) != 0x05) {
    printf("Error. Second four bits of ipv4 header should be 5, indicating header length is 20 bytes.\
            Program assumes struct ip_header length is fixed.");
    exit(-1);
  }
}



void send_ip_packet(
  unsigned char *header,
  struct SendSocket send_sockets[],
  struct RecvSocket *receiving_socket
) {
  
  struct SendSocket *active_sockets[4];
  uint16_t ipv4_packet_length, length_excl_headers, ehl, i;
  unsigned char protocol, destination_mac_address[6], source_mac_address[6],
  non_malicious_mac_address, active_socket_index, byte;

  ehl = ETHERNET_HEADER_LENGTH;

  //compute bytes to send besides header. Note the ipv4 length includes the header
  ipv4_packet_length = ntohs(* (uint16_t *) &header[ehl + 2]);
  length_excl_headers = ipv4_packet_length - IPV4_HEADER_LENGTH;

  protocol = header[ehl + 9];
  memcpy(destination_mac_address, &header[0], 6);
  memcpy(source_mac_address, &header[6], 6);

  //sockets to send ip packet will be stored in active_sockets. The active_socket_index
  //tracks the number of sockets to send data over.
  active_socket_index = 0;

  //packet should be sent to monitoring port, irrespective of whether it is malicious
  //or its protocol
  for (i = 0; i < 3; i++) 
    if (memcmp(destination_mac_address, monitoring_mac_address_starts[i], 3) == 0)
      active_sockets[active_socket_index++] = &send_sockets[MONITORING_SOCKET_INDEX];

  non_malicious_mac_address = 1;
  for (i = 0; i < 3; i++)
    if (memcmp(source_mac_address, malicious_mac_address_starts[i], 3) == 0)
      non_malicious_mac_address = 0;

  //if packet is not malicious, use protocol value to deduce whether it should
  //be sent to tcp or udp port (or neither).
  if (non_malicious_mac_address) {

    if (protocol == TCP_PROTOCOL_VALUE)
      active_sockets[active_socket_index++] = &send_sockets[TCP_SOCKET_INDEX];

    if (protocol == UDP_PROTOCOL_VALUE)
      active_sockets[active_socket_index++] = &send_sockets[UDP_SOCKET_INDEX];
  }

  //Send packet ipv4 and ethernet header
  for (i = 0; i < COMBINED_HEADER_LENGTH; i++) 
    send_byte_on_sockets(active_sockets, active_socket_index, header[i]);

  //Send packet payload
  for (i = 0; i < length_excl_headers; i++) {
    byte = get_non_EOF_byte(receiving_socket);
    send_byte_on_sockets(active_sockets, active_socket_index, byte);
  }  
}



void get_pdf_file() {

  struct RecvSocket receiving_socket;
  struct SendSocket sending_socket[3];
  struct PdfManager pdf_manager;
  int byte; 
  unsigned char first_byte, first_4_bytes[4], headers[COMBINED_HEADER_LENGTH], i;

  receiving_socket = initialize_receiving_socket();
  sending_socket[MONITORING_SOCKET_INDEX] = initialize_sending_socket_on_port(MONITORING_PORT);
  sending_socket[TCP_SOCKET_INDEX] = initialize_sending_socket_on_port(TCP_PORT);
  sending_socket[UDP_SOCKET_INDEX] = initialize_sending_socket_on_port(UDP_PORT);
  pdf_manager = initialize_pdf_manager();

  while (1) {

    if ((byte = get_byte(&receiving_socket)) == EOF)
      break;

    //if byte is not EOF, it can be safely narrowed to unsigned char
    first_byte = (unsigned char) byte;

    first_4_bytes[0] = first_byte;
    get_non_EOF_bytes(&receiving_socket, &first_4_bytes[1], 3);
    if (memcmp(first_4_bytes, ctfs, 4) == 0) {
      extract_ctfs_packet_stage_2(&pdf_manager, &receiving_socket);
      continue;
    }

    //if we've reached this point, we either have an ethernet/ip packet or a bug.
    //Attempt to read headers.
    memcpy(headers, first_4_bytes, 4);
    get_non_EOF_bytes(&receiving_socket, &headers[4], COMBINED_HEADER_LENGTH - 4);

    //Perform basic checks to see if headers appear valid
    validate_ip_packet(headers);

    //Assume packet is valid and send to relevant ports.
    send_ip_packet(headers, sending_socket, &receiving_socket);
  }

  construct_pdf_files(&pdf_manager);

  //Clean up sockets and memory allocations.
  cleanup_pdf_manager(&pdf_manager);
  for (i = 0; i < 3; i++)
    cleanup_sending_socket(&sending_socket[i]);
  cleanup_receiving_socket(&receiving_socket);
}



int main() {

  get_pdf_file();
  return 0;
}
