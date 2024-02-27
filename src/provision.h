#ifndef PROVISION_H
#define PROVISION_H

int provision_tag(
    FreefareTag tag,
    MifareDESFireAID new_aid,
    MifareDESFireKey default_3des,
    MifareDESFireKey default_aes,
    MifareDESFireKey application_master,
    MifareDESFireKey door_key,
    char *secret);

#endif //PROVISION_H