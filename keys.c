/*

Copyright 2015 Kakaroto

This software is distributed under the terms of the GNU General Public
License ("GPL") version 3, as published by the Free Software Foundation.

*/

#include "keys.h"
#include "tools.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "paged_file.h"

#define DEFAULT_KEYS_CONF_PATH "keys.conf"
static char *keys_conf_path = NULL;

#define parse_key(where)                        \
  int len = strlen (v);                         \
                                                \
  if (current_key->where || (len % 2) != 0)                     \
    goto error;                                                 \
  current_key->where = malloc (len / 2);                        \
  if (parse_hex (v, current_key->where, len / 2) != len / 2)    \
    goto error;

void
keys_set_path (const char *path)
{
  if (keys_conf_path)
    free (keys_conf_path);
  keys_conf_path = strdup (path);
}

Key *
keys_load (int *num_keys)
{
  Key *keys = NULL;

  if (keys_conf_path)
    keys = keys_load_from_file (keys_conf_path, num_keys);
  else
    keys = keys_load_from_file (DEFAULT_KEYS_CONF_PATH, num_keys);

  if (keys == NULL) {
    char buffer[1024];
    const char *path = getenv ("PS3_KEYS_PATH");

    if (path) {
      snprintf (buffer, sizeof(buffer), "%s/keys.conf", path);
      keys = keys_load_from_file (buffer, num_keys);
    }
    if (keys == NULL) {
      path = getenv ("HOME");

      if (path) {
        snprintf (buffer, sizeof(buffer), "%s/.ps3/keys.conf", path);
        keys = keys_load_from_file (buffer, num_keys);
      }
    }
  }

  return keys;
}

Key *
keys_load_from_file (const char *filename, int *num_keys)
{
  PagedFile fd = {0};
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
    while (i < len && line[i] != '=') {
      k[i] = line[i];
      i++;
    }
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
      current_key->type = strdup (v);
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
keys_find_by_revision (Key *keys, int num_keys, const char *type, u32 revision)
{
  int i;

  for (i = 0; i < num_keys; i++) {
    if (strcmp (keys[i].type, type) == 0 &&
        keys[i].revision == revision)
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
