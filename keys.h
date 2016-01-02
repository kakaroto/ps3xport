/*

Copyright 2015 Kakaroto

This software is distributed under the terms of the GNU General Public
License ("GPL") version 3, as published by the Free Software Foundation.

*/

#ifndef __KEYS_H__
#define __KEYS_H__ 1

#include <stdint.h>

#include "types.h"

#define KEY_TYPE_METLDR "metldr"
#define KEY_TYPE_LV1 "lv1"
#define KEY_TYPE_LV2 "lv2"
#define KEY_TYPE_ISO "iso"
#define KEY_TYPE_APP "app"
#define KEY_TYPE_NPDRM "npdrm"
#define KEY_TYPE_SC "sc"

typedef struct {
  char *name;
  char *type;
  union {
    struct {
      char major;
      char dot;
      char minor;
      char nano;
    };
    char version[4];
  };
  u32 revision;
  u8 *key;
  u8 *iv;
  u8 *public;
  u8 *private;
  u32 ctype;
} Key;

Key *keys_load (int *num_keys);
Key *keys_load_from_file (const char *filename, int *num_keys);
Key *keys_find_by_name (Key *keys, int num_keys, const char *name);
Key *keys_find_by_revision (Key *keys, int num_keys, const char *type, u32 revision);
void keys_free (Key *keys, int num_keys);
void keys_set_path (const char *path);

#endif /* __KEYS_H__ */
