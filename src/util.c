#include "./util.h"

MifareDESFireKey read_key_from_file(const char *filename) {
    uint8_t *key_bytes = malloc(17);
    memset(key_bytes, 0x00, 17);
    FILE *key_file = fopen(filename, "r");
    if(key_file == NULL)
    {
        printf("[e] error opening key file (%s): %s\n", filename, strerror(errno));
        return NULL;
    }

    for(int i=0; i<16; i++) {
        key_bytes[i] = fgetc(key_file);
        // printf("[i]: read byte from file: %d\n", key_bytes[i]);
    }

    fclose(key_file);

    return mifare_desfire_aes_key_new(key_bytes);
}

