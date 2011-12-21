// Copyright 2011            Code Monkeys
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt

#include "keys.h"
#include "tools.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "paged_file.h"

#define parse_key(where)                        \
  int len = strlen (v);                         \
                                                \
  if (current_key->where || (len % 2) != 0)                     \
    goto error;                                                 \
  current_key->where = malloc (len / 2);                        \
  if (parse_hex (v, current_key->where, len / 2) != len / 2)    \
    goto error;

Key *
keys_load_from_file (const char *filename, int *num_keys)
{
  PagedFile fd;
  Key *keys = NULL;
  Key *current_key = NULL;
  char *line = NULL;
  char k[1024];
  char v[1024];
  int i, j;
  int line_len = 1024;

  if (paged_file_open (&fd, filename, TRUE) == FALSE)
    return NULL;

  *num_keys = 0;
  while (paged_file_getline (&fd, &line, &line_len) != -1) {
    int len = strlen (line);

    if (len > 1024)
      continue;
    i = 0;
    j = 0;
    while (i < len && line[i] != '=')
      k[i] = line[i++];
    k[i++] = 0;
    if (i >= len)
      continue;
    while (i < len && line[i] != '\r' && line[i] != '\n')
       v[j++] = line[i++];
    v[j] = 0;
    if (j == 0 || k[0] == '#')
      continue;
    if (strcmp (k, "name") == 0) {
      (*num_keys)++;
      keys = realloc (keys, (*num_keys) * sizeof(Key));
      if (keys_find_by_name (keys, *num_keys - 1, v) != NULL)
        goto error;
      current_key = &keys[*num_keys - 1];
      memset (current_key, 0, sizeof(Key));
      memcpy (current_key->version, "1.00", 4);
      current_key->name = strdup (v);
    } else if (strcmp (k, "type") == 0) {
      if (strcmp (v, "metldr") == 0) {
        current_key->type = KEY_TYPE_METLDR;
      } else if (strcmp (v, "lv1") == 0) {
        current_key->type = KEY_TYPE_LV1;
      } else if (strcmp (v, "lv2") == 0) {
        current_key->type = KEY_TYPE_LV2;
      } else if (strcmp (v, "iso") == 0) {
        current_key->type = KEY_TYPE_ISO;
      } else if (strcmp (v, "app") == 0) {
        current_key->type = KEY_TYPE_APP;
      } else if (strcmp (v, "npdrm") == 0) {
        current_key->type = KEY_TYPE_NPDRM;
      } else if (strcmp (v, "sc") == 0) {
        current_key->type = KEY_TYPE_SC;
      } else {
        goto error;
      }
    } else if (strcmp (k, "version") == 0) {
      if (strlen (v) == 4)
        memcpy (current_key->version, v, 4);
      else
        goto error;
    } else if (strcmp (k, "revision") == 0) {
      current_key->revision = strtoul (v, NULL, 10);
    } else if (strcmp (k, "key") == 0) {
      parse_key (key);
    } else if (strcmp (k, "iv") == 0) {
      parse_key (iv);
    } else if (strcmp (k, "public") == 0) {
      parse_key (public);
    } else if (strcmp (k, "private") == 0) {
      parse_key (private);
    } else if (strcmp (k, "ctype") == 0) {
      current_key->ctype = strtoul (v, NULL, 10);
    }
  }

  free (line);
  paged_file_close (&fd);
  return keys;
 error:
  free (line);
  free (keys);
  paged_file_close (&fd);
  return NULL;
}

Key *
keys_find_by_name (Key *keys, int num_keys, const char *name)
{
  int i;

  for (i = 0; i < num_keys; i++) {
    if (strcmp (keys[i].name, name) == 0)
      return &keys[i];
  }
  return NULL;
}

Key *
keys_find_by_revision (Key *keys, int num_keys, KeyType type, u32 revision)
{
  int i;

  for (i = 0; i < num_keys; i++) {
    if (keys[i].type == type && keys[i].revision == revision)
      return &keys[i];
  }
  return NULL;
}

void
keys_free (Key *keys, int num_keys)
{
  int i;

  for (i = 0; i < num_keys; i++) {
    free (keys[i].name);
    free (keys[i].key);
    free (keys[i].iv);
    free (keys[i].public);
    free (keys[i].private);
  }
  free (keys);
}
