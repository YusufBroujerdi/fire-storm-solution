#pragma once

#include "ctfs_packet_handling.h"
#include "socket_management.h"

//An interface for managing all file id fragments collectively.
struct PdfManager {
  struct PdfFileIdHandler **pdf_address_by_file_id;
  struct PdfFileIdHandler *pdf_handlers;
  uint16_t number_of_handlers;
  uint16_t max_number_of_handlers;
};

//struct for managing CTFS header and its interpretations efficiently.
union CtfsHeader {
  unsigned char data[16];
  uint32_t words[4];
  struct {
    unsigned char ctfs_bytes[4];
    unsigned char sequence_bytes[2];
    unsigned char length_bytes[2];
    unsigned char file_id;
    unsigned char checksum_bytes[4];
    unsigned char padding[3];
  };
};

union Word {
  uint32_t whole_word;
  uint8_t data[4];
};

extern uint8_t UseChecksum;
extern unsigned char ctfs[4];

struct PdfManager initialize_pdf_manager();
void construct_pdf_files(struct PdfManager *manager);
void cleanup_manager(struct PdfManager *manager);
void extract_ctfs_packet_stage_2(
  struct PdfManager *manager,
  struct RecvSocket *byte_stream
);
