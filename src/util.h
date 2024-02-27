#ifndef UTIL_H
#define UTIL_H
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "freefare.h"

MifareDESFireKey read_key_from_file(const char *filename);

#endif//UTIL_H