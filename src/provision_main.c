#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <time.h>

#include "nfc/nfc-types.h"
#include "nfc/nfc.h"
#include "freefare.h"

#include "./provision.h"

const uint8_t zeroes[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

const char *charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
void random_string(ssize_t length, char *dst) {
    for(int i=0; i < length; i++) {
        dst[i] = charset[rand() % strlen(charset)];
    }
}

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
        printf("[i]: read byte from file: %d\n", key_bytes[i]);
    }

    fclose(key_file);

    return mifare_desfire_aes_key_new(key_bytes);
}

int main()
{
    int res = 0;
    nfc_context *nfc_ctx;

    srand(time(NULL));

    printf("[i] airlock provisioner started.\n");

    nfc_init(&nfc_ctx);
    if (nfc_ctx == NULL)
    {
        printf("[e] error on nfc_init.\n");
        return 1;
    }

    nfc_device *device;
    device = nfc_open(nfc_ctx, NULL);
    if (!device)
    {
        printf("[e] error opening nfc_device\n");
        return 1;
    }

    FreefareTag *tags = NULL;
    tags = freefare_get_tags(device);
    if (!tags)
    {
        nfc_close(device);
        printf("[e] error getting tags from nfc device\n");
        return 2;
    }


    MifareDESFireKey default_3des = mifare_desfire_3des_key_new(zeroes);
    MifareDESFireKey default_aes = mifare_desfire_aes_key_new(zeroes);

    MifareDESFireKey application_master_key = read_key_from_file("application_master_key.aes");
    if (!application_master_key)
    {
        printf("[e] error reading application master key.\n");
        return 1;
    }

    MifareDESFireKey door_key = read_key_from_file("door_key.aes");
    if (!door_key)
    {
        printf("[e] error reading door key.\n");
        return 1;
    }

    char secret[33];
    memset(secret, 0x00, 33);
    random_string(32, secret);
    printf("[i] generated secret: %s\n", secret);

    for (int i = 0; (res <= 0) && tags[i]; i++)
    {
        res = provision_tag(
            tags[i],
            mifare_desfire_aid_new(420),
            default_3des,
            default_aes,
            application_master_key,
            door_key,
            secret
        );
        if(res > 0) {
            printf("[e] error occurred during provisioning: %s\n", freefare_strerror(tags[i]));
            continue;
        }
        printf("[i] provisioning done.\n");
    }

    freefare_free_tags(tags);
    nfc_close(device);

    nfc_exit(nfc_ctx);

    return 0;
}