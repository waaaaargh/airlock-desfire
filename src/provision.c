#include "nfc/nfc.h"
#include "nfc/nfc-types.h"
#include "freefare.h"

uint8_t provision_tag(
    FreefareTag tag,
    MifareDESFireAID new_aid,
    MifareDESFireKey default_3des,
    MifareDESFireKey default_aes,
    MifareDESFireKey application_master,
    MifareDESFireKey door,
    char *secret)
{
    int res;

    if (MIFARE_DESFIRE != freefare_get_tag_type(tag))
    {
        printf("[i] found non-desfire tag.\n");
        return 1;
    }

    printf("[i] found %s \n", freefare_get_tag_friendly_name(tag));

    res = mifare_desfire_connect(tag);
    if (res < 0)
    {
        printf("[e] could not connect to mifare desfire tag.\n");
        return 1;
    }

    res = mifare_desfire_authenticate(tag, 0, default_3des);
    if (res < 0)
    {
        printf("[e] could not authenticate to mifare desfire tag with default key.\n");
        return 1;
    }
    printf("[i] authenticated to desfire tag with default key \n");

    MifareDESFireAID card_aid = mifare_desfire_aid_new(0);
    res = mifare_desfire_select_application(tag, card_aid);
    if (res < 0)
    {
        printf("[e] error selecting application 0 on mifare desfire tag.\n");
        return 1;
    }
    printf("[i] selected application 0 on mifare desfire tag.\n");

    // Special Sauce:
    //   https://www.cardlogix.com/wp-content/uploads/MIFARE-Application-Programming-Guide-for-DESFfire_rev.e.pdf p.15
    res = mifare_desfire_create_application_aes(tag, new_aid, MDAPP_SETTINGS(0x00, 0b1, 0b1, 0b1, 0b1), 0b10001010);
    if (res < 0)
    {
        printf("[e] error creating application on mifare desfire tag.\n");
        return 1;
    }
    printf("[i] created application on mifare desfire tag.\n");

    res = mifare_desfire_select_application(tag, new_aid);
    if (res < 0)
    {
        printf("[e] error selecting application 420 on mifare desfire tag.\n");
        return 1;
    }

    printf("[i] selected new application on mifare desfire tag.\n");

    res = mifare_desfire_authenticate(tag, 0, default_aes);
    if (res < 0)
    {
        printf("[e] error authentication against new application w/ default application key.\n");
        return 1;
    }
    printf("[i] authenticated against new application w/ default application key.\n");

    res = mifare_desfire_change_key(tag, 0, application_master, default_aes);
    if (res < 0)
    {
        printf("[e] error changing application master key.\n");
        return 1;
    }
    printf("[i] changed application master key. \n");

    res = mifare_desfire_authenticate(tag, 0, application_master);
    if (res < 0)
    {
        printf("[e] error authentication against new application w/ new application master key.\n");
        return 1;
    }
    printf("[i] authenticated against new application w/ new application master key.\n");

    res = mifare_desfire_change_key(tag, 1, door, default_aes);
    if (res < 0)
    {
        printf("[e] error installing door key.\n");
        return 1;
    }
    printf("[i] installed door key. \n");

    res = mifare_desfire_authenticate(tag, 1, door);
    if (res < 0)
    {
        printf("[e] error authentication against new application w/ new door key.\n");
        return 1;
    }
    printf("[i] authenticated against new application w/ new door key.\n");

    res = mifare_desfire_authenticate(tag, 0, application_master);
    if (res < 0)
    {
        printf("[e] error authentication against new application w/ new application master key.\n");
        return 1;
    }
    printf("[i] authenticated against new application w/ new application master key.\n");

    res = mifare_desfire_create_std_data_file(tag, 0, 0b00000011, MDAR(MDAR_KEY1, MDAR_KEY0, MDAR_KEY0, MDAR_KEY0), 32);
    if (res < 0)
    {
        printf("[e] error creating secret file.\n");
        return 1;
    }
    printf("[i] created secret file. \n");

    res = mifare_desfire_write_data(tag, 0, 0, 32, (void *)secret);
    if (res < 0)
    {
        printf("[e] error writing secret.\n");
        return 1;
    }
    printf("[i] wrote %d bytes secret to file: %s\n", res, secret);

    res = mifare_desfire_disconnect(tag);
    if (res < 0)
    {
        printf("[e] error disconnecting from mifare desfire tag.\n");
        return 1;
    }

    return 0;
}
