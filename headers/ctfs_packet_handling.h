#pragma once

#include <stdint.h>

#include "socket_management.h"

//Struct will be helpful in reordering PDF packets later on
struct PdfFragment {
  unsigned char *payload;
  uint16_t sequence_number;
  uint16_t length;
};



//An interface for managing fragments of different file ids.
struct PdfFileIdHandler {
  unsigned char *payload_storage;
  struct PdfFragment *fragments;
  uint64_t payload_storage_size;
  uint64_t fragment_max_index;
  uint64_t payload_storage_index;
  uint64_t fragment_index;
  unsigned char file_id;
};



struct PdfFileIdHandler initialize_file_id_handler(unsigned char file_id);
void extend_payload_storage(struct PdfFileIdHandler *file_id_handler);
void extend_fragments_storage(struct PdfFileIdHandler *file_id_handler);

void extract_ctfs_packet(
  struct PdfFileIdHandler *handler,
  struct RecvSocket *byte_stream
);

void quicksort_fragments(struct PdfFragment *fragments, uint32_t length);
void assemble_pdf_from_fragments(struct PdfFileIdHandler *file_id_handler);
void cleanup_file_id_handler(struct PdfFileIdHandler *file_id_handler);
