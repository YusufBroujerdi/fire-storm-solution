#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../headers/stage_2_ctfs_packet_handling.h"
#include "../headers/socket_management.h"

//Useful for logic
unsigned char ctfs[4] = {'C', 'T', 'F', 'S'};

//Our strategy is to add a new interface layer for handling multiple file
//ids at once, building off the existing code for handling pdf fragments.
struct PdfManager initialize_pdf_manager() {

  struct PdfFileIdHandler **addresses_by_file_id, *file_id_handlers;
  uint64_t addresses_by_file_id_size, file_id_handlers_size;

  //Allocate storage for PdfFileIdHandlers. 32 pdf files seems like
  //a reasonable upper bound which can be extended later if necessary.
  file_id_handlers_size = 32 * sizeof(struct PdfFileIdHandler);
  file_id_handlers = malloc(file_id_handlers_size);
  if (file_id_handlers == NULL) {
    printf("allocating storage for file id handlers failed\n");
    exit(-1);
  }

  //Since the protocol only provides one byte for file id, we know
  //the file id will always be between 0 and 255. We can maintain
  //an array of 255 pointers to PdfFileIdHandlers to ensure finding
  //the handler of a file id remains fast, without resorting to
  //implementing a hash table or binary search tree.
  addresses_by_file_id_size = 256 * sizeof(struct PdfFileIdHandler *);
  addresses_by_file_id = malloc(addresses_by_file_id_size);
  if (addresses_by_file_id == NULL) {
    printf("allocating storage for file id address array failed\n");
    exit(-1);
  }

  //We will know whether a file id already has a PdfFileIdHandler
  //by whether its address in the array is set. So make sure values
  //are initialized to NULL.
  for (uint16_t address_index = 0; address_index < 256; address_index++) 
    addresses_by_file_id[address_index] = NULL;

  struct PdfManager manager = {
    .pdf_handlers = file_id_handlers,
    .pdf_address_by_file_id = addresses_by_file_id,
    .number_of_handlers = 0,
    .max_number_of_handlers = 32
  };

  return manager;
}



void extend_handler_storage(struct PdfManager *manager) {

  struct PdfFileIdHandler *new_handler_storage;
  uint64_t new_storage_size;

  new_handler_storage = realloc(
    manager->pdf_handlers,
    manager->max_number_of_handlers * 2 * sizeof(struct PdfFileIdHandler)
  );
  if (new_handler_storage == NULL) {
    printf("Failed to allocate more storage for PdfFileIdHandlers");
    exit(-1);
  }

  manager->pdf_handlers = new_handler_storage;
  manager->max_number_of_handlers *= 2;
}



void construct_pdf_files(struct PdfManager *manager) {

  for (uint16_t i = 0; i < manager->number_of_handlers; i++)
    assemble_pdf_from_fragments(&manager->pdf_handlers[i]);
}



void cleanup_pdf_manager(struct PdfManager *manager) {

  for (uint16_t i = 0; i < manager->number_of_handlers; i++)
    cleanup_file_id_handler(&manager->pdf_handlers[i]);

  free(manager->pdf_handlers);
  free(manager->pdf_address_by_file_id);
}



void accumulate_checksum(uint32_t *accumulator, uint32_t word) {

  uint8_t leftmost_bit;

  *accumulator += word;
  leftmost_bit = (*accumulator & 0x80000000) != 0;
  *accumulator = *accumulator << 1 | leftmost_bit;
}



//Reimplement ctfs packet extraction for stage 2. This duplicates some code but
//stops stage 1 depending on stage 2.
void extract_ctfs_packet_stage_2(
  struct PdfManager *manager,
  struct RecvSocket *byte_stream
) {

  union CtfsHeader ctfs_header;
  union Word word;
  unsigned char next_byte, file_id;
  uint16_t sequence_number, length, n, i;
  uint32_t checksum, accumulator;
  struct PdfFileIdHandler *handler;
  struct PdfFragment *new_fragment;

  //Read data into CTFS header
  memcpy(ctfs_header.ctfs_bytes, ctfs, 4);
  get_non_EOF_bytes(byte_stream, ctfs_header.data + 4, 12);

  //Extracting length, sequence number and checksum this way is endian-agnostic. Though
  //assuming network is big endian and host is little endian also seems reasonable.
  sequence_number = ntohs(*((uint16_t *) &ctfs_header.sequence_bytes));
  length = ntohs(*((uint16_t *) &ctfs_header.length_bytes));

  //Make an aligned copy of the checksum before operating on it.
  memcpy(&checksum, &ctfs_header.checksum_bytes, 4);
  checksum = ntohl(checksum);

  //Now we have the checksum, replace the checksum field with "CTFS".
  memcpy(&ctfs_header.checksum_bytes, ctfs, 4);

  //Find correct handler from file id. Initialize it if necessary.
  if ((handler = manager->pdf_address_by_file_id[ctfs_header.file_id]) == NULL) {

    //If handler storage full, extend handler storage
    if (manager->number_of_handlers == manager->max_number_of_handlers) 
      extend_handler_storage(manager);

    //Allocate handler from available handlers.
    handler = &manager->pdf_handlers[manager->number_of_handlers++];

    //Make sure address is set in handler addresses going forward
    manager->pdf_address_by_file_id[ctfs_header.file_id] = handler;
  }

  if (handler->fragment_index == handler->fragments_size)
    extend_fragments_storage(handler);

  new_fragment = handler->fragments + handler->fragment_index++;
  new_fragment->sequence_number = sequence_number;
  new_fragment->payload = handler->payload_storage + handler->payload_storage_index;
  new_fragment->length = length;

  accumulator = 0;
  for (n = 0; n < 4; n++) 
    accumulate_checksum(&accumulator, ctfs_header.words[n]);

  for (n = 0; n < length; n++) {

    //If payload storage has run out of memory, extend it.
    if (handler->payload_storage_size == handler->payload_storage_index)
      extend_payload_storage(handler);

    next_byte = get_non_EOF_byte(byte_stream);

    //Add byte to checksum word. Add word to accumulator if word is complete.
    //We can figure out whether the word is complete using the payload index mod 4.
    word.data[n % 4] = next_byte;
    if (n % 4 == 3) {
      accumulate_checksum(&checksum, word.whole_word);
    }

    handler->payload_storage[handler->payload_storage_index++] = next_byte;
  }

  //If data length was not divisible by 4, we'll need to add one more partial word.
  if (length % 4 != 0) {
    
    //Pad remaining word with 0s
    for (i = length % 4; i % 4 != 0; i++)
      word.data[i] = 0;

    accumulate_checksum(&checksum, word.whole_word);
  }

  //If we're using the checksum and it's incorrect, discard fragment by resetting index.
  if (UseChecksum && checksum != accumulator)
    handler->fragment_index--;
}
