#define DATA_ADDRESS 	0x00300000
#define BUFFER_LENGTH   20

int main(void) {
  unsigned char *data_buf = (unsigned char *) DATA_ADDRESS;

  if (data_buf[20] != 0) {
    // Cause an 'invalid read' crash if data[0..3] == '\x01\x02\x03\x04'
    unsigned char invalid_read = *(unsigned char *) 0x00000000;
  } else if (data_buf[0] > 0x10 && data_buf[0] < 0x20 && data_buf[1] > data_buf[2]) {
    // Cause an 'invalid read' crash if (0x10 < data[0] < 0x20) and data[1] > data[2]
    unsigned char invalid_read = *(unsigned char *) 0x00000000;
  } else if (data_buf[9] == 0x00 && data_buf[10] != 0x00 && data_buf[11] == 0x00) {
    // Cause a crash if data[10] is not zero, but [9] and [11] are zero
    unsigned char invalid_read = *(unsigned char *) 0x00000000;
  } else {
    unsigned char match1[] = "XYZ1ABCDEFGHIJKLMN";  // Example 20-byte hardcoded string
    unsigned char match2[] = "ABCDEFGHIJKLMNOPQRST"; // Another 20-byte string

    // Case 1: Return 0 if buffer exactly matches "XYZ1ABCDEFGHIJKLMN"
    int i;
    for (i = 0; i < BUFFER_LENGTH; i++) {
      if (data_buf[i] != match1[i]) break;
    }
    if (i == BUFFER_LENGTH) return 0;

    // Case 2: Return 0 if buffer exactly matches "ABCDEFGHIJKLMNOPQRST"
    for (i = 0; i < BUFFER_LENGTH; i++) {
      if (data_buf[i] != match2[i]) break;
    }
    if (i == BUFFER_LENGTH) return 0;

    // Case: Always false condition (unreachable)
    unsigned char unreachable[] = {0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00};
    for (i = 0; i < BUFFER_LENGTH; i++) {
      if (data_buf[i] != unreachable[i]) break;
    }
    if (i == BUFFER_LENGTH) {
      unsigned char invalid_read = *(unsigned char *) 0x00000000;
    }

    // Case: Every other character in the buffer is 'A'
    for (i = 0; i < BUFFER_LENGTH; i += 2) {
      if (data_buf[i] != 'A') break;
    }
    if (i >= BUFFER_LENGTH) {
      unsigned char invalid_read = *(unsigned char *) 0x00000000;
    }

    // Case: Check for obscure Unicode characters over 20-byte buffer
    unsigned char unicode_check[] = {0xE2, 0x98, 0xA0, 0xE2, 0x98, 0xA0, 0xE2, 0x98, 0xA0, 0xE2, 0x98, 0xA0, 0xE2, 0x98, 0xA0, 0xE2, 0x98, 0xA0, 0xE2, 0x98, 0xA0};
    for (i = 0; i < BUFFER_LENGTH; i++) {
      if (data_buf[i] != unicode_check[i]) break;
    }
    if (i == BUFFER_LENGTH) {
      unsigned char invalid_read = *(unsigned char *) 0x00000000;
    }
  }

  return 0;
}

