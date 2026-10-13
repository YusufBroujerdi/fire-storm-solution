#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "../headers/socket_management.h"
#include "../headers/ctfs_packet_handling.h"



struct PdfFileIdHandler initialize_file_id_handler(unsigned char file_id) {

  unsigned char *payload_storage;
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

  struct PdfFileIdHandler handler = {
    .payload_storage = payload_storage,
    .payload_storage_index = 0,
    .payload_storage_size = payload_storage_size,
    .fragments = fragments,
    .fragment_index = 0,
    .fragments_size = fragments_size,
    .file_id = file_id
  };

  return handler;
}



void extend_payload_storage(struct PdfFileIdHandler *file_id_handler) {

  unsigned char *new_payload_storage;
  
  new_payload_storage = realloc(
    file_id_handler->payload_storage,
    file_id_handler->payload_storage_size * 2
  );
  if (new_payload_storage == NULL) {
    printf("Attempt to extend payload storage failed.\n");
    exit(-1);
  }

  file_id_handler->payload_storage = new_payload_storage;
  file_id_handler->payload_storage_size *= 2;
}



void extend_fragments_storage(struct PdfFileIdHandler *file_id_handler) {

  struct PdfFragment *new_fragments_storage;
  
  new_fragments_storage = realloc(
    file_id_handler->fragments,
    file_id_handler->fragments_size * 2 * sizeof(struct PdfFragment)
  );
  if (new_fragments_storage == NULL) {
    printf("Attempt to extend fragment storage failed.\n");
    exit(-1);
  }

  file_id_handler->fragments = new_fragments_storage;
  file_id_handler->fragments_size *= 2;
}



void cleanup_file_id_handler(struct PdfFileIdHandler *file_id_handler) {
  free(file_id_handler->fragments);
  free(file_id_handler->payload_storage);
}



//sorts fragments by sequence number, via the quicksort algorithm.
void quicksort_fragments(
  struct PdfFragment *fragments,
  uint32_t length
) {

  uint32_t pivot_index, last_index, next_low, length_of_low, length_of_high;
  struct PdfFragment tmp, *address_of_high;

  //Since this algorithm is recursive, a base case is needed to ensure recursion
  //terminates at the leaves
  if (length == 1 || length == 0) {
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
  for (uint32_t i = 0; i < last_index; i++) {
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



void assemble_pdf_from_fragments(struct PdfFileIdHandler *file_id_handler) {

  FILE *file;
  struct PdfFragment *fragment;
  unsigned char *byte, *end_byte;
  char pdf_file_name[8];

  //Sort fragments by sequence number.
  quicksort_fragments(
    file_id_handler->fragments,
    file_id_handler->fragment_index
  );

  //Construct pdf file name, which must be at most 7 chars long.
  sprintf(pdf_file_name, "%d.pdf", file_id_handler->file_id);
  //Prepare to write to file
  file = fopen(pdf_file_name, "w");
  if (file == NULL) {
    printf("Failed to open file to put pdf.\n");
    exit(-1);
  }

  //For each fragment, for each byte in fragment payload, put byte in file.
  for(
    fragment = file_id_handler->fragments;
    fragment < file_id_handler->fragments + file_id_handler->fragment_index;
    fragment++
  ) {
    end_byte = fragment->payload + fragment->length;
    for(byte = fragment->payload; byte != end_byte; byte++) {
      if (fputc(*byte, file) == EOF) {
        printf("Failed to write byte to file.\n");
        exit(-1);
      }
    }
  }

  fclose(file);
}



//Extract payload of CTFS packet, supposing "CTFS" has just been read.
void extract_ctfs_packet(
  struct PdfFileIdHandler *handler,
  struct RecvSocket *byte_stream
) {

  unsigned char sequence_byte[2], length_byte[2], next_byte;
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
  new_fragment->length = length;

  for (uint16_t n = 0; n < length; n++) {

    //If payload storage has run out of memory, extend it.
    if (handler->payload_storage_size == handler->payload_storage_index)
      extend_payload_storage(handler);

    next_byte = get_non_EOF_byte(byte_stream);
    handler->payload_storage[handler->payload_storage_index++] = next_byte;
  }
}
