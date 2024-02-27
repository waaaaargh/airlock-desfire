#include <stdio.h>
#include <unistd.h>

#include "nfc/nfc-types.h"
#include "nfc/nfc.h"
#include "freefare.h"

#include "./util.h"
#include "curl/curl.h"

#define NFC_MAX_TARGETS 5
#define BACKEND_URL "http://localhost:8000"
#define SECRET_LENGTH 32

void call_credential_validator(char *secret) {
    CURL *hdl = curl_easy_init();

    char *postfields = (char *) malloc(128);
    sprintf(postfields, "secret=%s", secret);

    curl_easy_setopt(hdl, CURLOPT_URL, BACKEND_URL);
    curl_easy_setopt(hdl, CURLOPT_POSTFIELDS, postfields);
    curl_easy_setopt (hdl, CURLOPT_VERBOSE, 0);

    CURLcode success = curl_easy_perform(hdl);
    if(success != CURLE_OK) {
        printf("[e] calling backend failed.\n");
    }
}

bool validate_card(FreefareTag tag, MifareDESFireAID aid, MifareDESFireKey key) {
    int res = 0;

    res = mifare_desfire_connect(tag);
    if (res < 0)
    {
        printf("[e] error connecting to desfire tag.\n");
        return false;
    }
    printf("[i] connected to desfire tag.\n");
    
    res = mifare_desfire_select_application(tag, aid);
    if (res < 0)
    {
        printf("[e] error selecting application 420 on mifare desfire tag.\n");
        return false;
    }
    printf("[i] selected application 420.\n");

    res = mifare_desfire_authenticate(tag, 1, key);
    if (res < 0)
    {
        printf("[e] error authentication against new application w/ reader key.\n");
        return 1;
    }
    printf("[i] authenticated against new application w/ reader key.\n");

    char *secret = (char *)malloc(SECRET_LENGTH+1);
    memset(secret, 0x00, SECRET_LENGTH+1);
    res = mifare_desfire_read_data_ex(tag, 0, 0, SECRET_LENGTH, secret, 0b00000011);
    printf("[i] read %d bytes from file.\n", res);
    if (res < 0)
    {
        printf("[e] error reading secret file: %s\n", freefare_strerror(tag));
        return 1;
    }
    printf("[i] read secret file.\n");

    call_credential_validator(secret);

    return true;
}

int main()
{
    int res = 0;

    MifareDESFireKey door_key = read_key_from_file("door_key.aes");
    if (!door_key)
    {
        printf("[e] error reading door key.\n");
        return 1;
    }
    MifareDESFireAID aid = mifare_desfire_aid_new(420);

    nfc_context *ctx;
    nfc_init(&ctx);
    if (ctx == NULL)
    {
        printf("[e] error on nfc_init.\n");
        return 1;
    }

    curl_global_init(CURL_GLOBAL_DEFAULT);

    nfc_device *device;

    nfc_modulation nm = { .nmt = NMT_ISO14443A, .nbr = NBR_106 };
    nfc_target tgts[NFC_MAX_TARGETS];

    bool exit = false;
    do {
        device = nfc_open(ctx, NULL);
        if (!device)
        {
            printf("[e] error opening nfc_device\n");
            return 1;
        }

        res = nfc_initiator_init(device);
        if(res < 0) {
            printf("[e] error initializing initiator\n");
            return 1;
        }

        res = nfc_initiator_list_passive_targets(device, nm, tgts, NFC_MAX_TARGETS);

        for(int i=0; i<res; i++) {
            if(tgts[i].nm.nmt == NMT_ISO14443A) {
                FreefareTag tag = freefare_tag_new(device, tgts[i]);
                if(validate_card(tag, aid, door_key)) {
                    printf("[e] found valid card.\n");
                    usleep(1000000);
                }
                else {
                    printf("[e] invalid card.\n");
                }
            }
        }

        nfc_close(device);
        usleep(150000);

    } while(!exit);


    nfc_exit(ctx);
    return res;
}