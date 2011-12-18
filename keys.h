// Copyright 2011            Code Monkeys
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt

#ifndef __KEYS_H__
#define __KEYS_H__ 1

#include <stdint.h>

#include "types.h"

typedef enum {
  KEY_TYPE_METLDR,
  KEY_TYPE_LV1,
  KEY_TYPE_LV2,
  KEY_TYPE_ISO,
  KEY_TYPE_APP,
  KEY_TYPE_NPDRM,
  KEY_TYPE_SC,
} KeyType;

typedef struct {
  char *name;
  KeyType type;
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

Key *keys_load_from_file (const char *filename, int *num_keys);
Key *keys_find_by_name (Key *keys, int num_keys, const char *name);
Key *keys_find_by_revision (Key *keys, int num_keys, KeyType type, u32 revision);
void keys_free (Key *keys, int num_keys);

#endif /* __KEYS_H__ */
