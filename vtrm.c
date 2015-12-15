/*

Copyright 2015 Kakaroto

This software is distributed under the terms of the GNU General Public
License ("GPL") version 3, as published by the Free Software Foundation.

*/

#include <stdlib.h>
#include <string.h>

#include "tools.h"
#include "types.h"
#include "common.h"
#include "keys.h"
#include "vtrm.h"

Key *keys = NULL;
int num_keys = 0;

static void sc_decrypt (u32 type, u8 *laid_paid, u8 *iv, u8 *in, u32 in_size, u8 *out);
static void sc_encrypt (u32 type, u8 *laid_paid, u8 *iv, u8 *in, u32 in_size, u8 *out);

void
vtrm_encrypt_with_portability (u32 type, u8 *buffer, u8 *iv)
{
  u32 real_type;
  u8 laid_paid[16] = {0};

  switch ( type )
  {
    case 0:
      real_type = 1;
      break;
    case 3:
      real_type = 5;
      break;
    case 1:
      real_type = 3;
      break;
    case 2:
      real_type = 2;
      break;
    default:
      die ("vtrm_encrypt_with_portability Unknown method\n");
      break;
  }
  sc_encrypt (real_type, laid_paid, iv, buffer, 0x40, buffer);
}

void
vtrm_encrypt (u32 type, u8 *buffer, u8 *iv)
{
  u64 laid_paid[2];

  laid_paid[0] = TO_BE (64, 0x1070000002000001ULL);
  switch ( type )
  {
    case 0:
      laid_paid[0] = laid_paid[1] = -1;
      break;
    case 1:
      laid_paid[1] = TO_BE (64, 0x1070000000000001ULL);
      break;
    case 2:
      laid_paid[1] = 0;
    case 3:
      laid_paid[1] = TO_BE (64, 0x10700003FF000001ULL);
      break;
    default:
      die ("vtrm_encrypt Unknown method\n");
      break;
  }
  sc_encrypt (3, (u8 *)laid_paid, iv, buffer, 0x40, buffer);
}

void
vtrm_encrypt_master (u64 laid, u64 paid, u8 *buffer, u8 *iv)
{
  u64 laid_paid[2];

  laid_paid[0] = TO_BE (64, laid);
  laid_paid[1] = TO_BE (64, paid);

  sc_encrypt (4, (u8 *)laid_paid, iv, buffer, 0x40, buffer);
}

static void
sc_encrypt (u32 type, u8 *laid_paid, u8 *iv, u8 *in, u32 in_size, u8 *out)
{
  Key *sc_key;
  u8 key[16];
  int i;

  if (type > 5)
    die ("sc_encrypt: Invalid key type\n");

  if (keys == NULL) {
    keys = keys_load (&num_keys);
    if (keys == NULL)
      die ("Unable to load necessary keys from\n");
  }

  sc_key = keys_find_by_revision (keys, num_keys, KEY_TYPE_SC, type);
  if (sc_key == NULL)
      die ("sc_encrypt: Unknown key\n");

  memcpy (key, sc_key->key, 16);
  for (i = 0; i < 16; i++)
    key[i] ^= laid_paid[i];
  aes128cbc_enc (key, iv, in, in_size, out);
}

void
vtrm_decrypt_with_portability (u32 type, u8 *buffer, u8 *iv)
{
  u32 real_type;
  u8 laid_paid[16] = {0};

  switch ( type )
  {
    case 0:
      real_type = 1;
      break;
    case 3:
      real_type = 5;
      break;
    case 1:
      real_type = 3;
      break;
    case 2:
      real_type = 2;
      break;
    default:
      die ("vtrm_encrypt_with_portability Unknown method\n");
      break;
  }
  sc_decrypt (real_type, laid_paid, iv, buffer, 0x40, buffer);
}

void
vtrm_decrypt (u32 type, u8 *buffer, u8 *iv)
{
  u64 laid_paid[2];

  laid_paid[0] = TO_BE (64, 0x1070000002000001ULL);
  switch ( type )
  {
    case 0:
      laid_paid[0] = laid_paid[1] = -1;
      break;
    case 1:
      laid_paid[1] = TO_BE (64, 0x1070000000000001ULL);
      break;
    case 2:
      laid_paid[1] = 0;
    case 3:
      laid_paid[1] = TO_BE (64, 0x10700003FF000001ULL);
      break;
    default:
      die ("vtrm_encrypt Unknown method\n");
      break;
  }
  sc_decrypt (3, (u8 *)laid_paid, iv, buffer, 0x40, buffer);
}

void
vtrm_decrypt_master (u64 laid, u64 paid, u8 *buffer, u8 *iv)
{
  u64 laid_paid[2];

  laid_paid[0] = TO_BE (64, laid);
  laid_paid[1] = TO_BE (64, paid);

  sc_decrypt (4, (u8 *)laid_paid, iv, buffer, 0x40, buffer);
}

static void
sc_decrypt (u32 type, u8 *laid_paid, u8 *iv, u8 *in, u32 in_size, u8 *out)
{
  Key *sc_key;
  u8 key[16];
  int i;

  if (type > 5)
    die ("sc_encrypt: Invalid key type\n");

  if (keys == NULL) {
    keys = keys_load (&num_keys);
    if (keys == NULL)
      die ("Unable to load necessary keys from\n");
  }

  sc_key = keys_find_by_revision (keys, num_keys, KEY_TYPE_SC, type);
  if (sc_key == NULL)
      die ("sc_encrypt: Unknown key\n");

  memcpy (key, sc_key->key, 16);
  for (i = 0; i < 16; i++)
    key[i] ^= laid_paid[i];
  aes128cbc (key, iv, in, in_size, out);
}

/*
void tst ()
{
  u8 buffer[0x40];
  // x-platform-passphrase
  u8 key1[0x40] = {0x70, 0xE6, 0xB0, 0x3F, 0x7A, 0x36, 0x4D, 0x04,
                     0x09, 0x1E, 0x92, 0x3D, 0x49, 0x2E, 0xAB, 0x66,
                     0xB4, 0x96, 0xD3, 0xA4, 0xD9, 0xE4, 0x0E, 0x10,
                     0x7B, 0x91, 0x1E, 0x1B, 0x8B, 0x04, 0xA7, 0xF0,
                     0x55, 0xC5, 0x5E, 0x6F, 0x7A, 0xA8, 0x37, 0x4D,
                     0x05, 0x16, 0x9A, 0xCB, 0xFF, 0xDF, 0xFB, 0x74,
                     0xE8, 0x6F, 0xC3, 0xD0, 0x20, 0x07, 0x8D, 0x06,
                     0x11, 0x2E, 0xBE, 0x84, 0x42, 0x8A, 0x8A, 0x72};
  // x-platform-passphrase fallback
  u8 key2[0x40] = {0x09, 0x13, 0x8F, 0x12, 0x48, 0x4E, 0xA4, 0xF0,
                   0xD0, 0x4C, 0xED, 0xF4, 0xB8, 0x22, 0x80, 0xE4,
                   0x3C, 0xB5, 0x88, 0x76, 0x75, 0x03, 0xD5, 0xEF,
                   0xB1, 0x70, 0xAA, 0x19, 0x4D, 0x42, 0x7D, 0x4F,
                   0xCA, 0xD8, 0x6C, 0x5A, 0x2B, 0xE0, 0xC3, 0x80,
                   0x74, 0x22, 0x86, 0x75, 0x10, 0x5D, 0x40, 0x99,
                   0x63, 0x01, 0x38, 0x06, 0x79, 0x59, 0xB9, 0x62,
                   0x96, 0x53, 0xDD, 0x67, 0x7D, 0x24, 0x4F, 0xA3};
  // usb dongle master key
  u8 key3[0x40] = {0x22, 0xD5, 0xD1, 0x8C, 0xFF, 0xE2, 0x4F, 0xAC,
                   0xEC, 0x72, 0xA2, 0x42, 0xA7, 0x18, 0x98, 0x10,
                   0x25, 0x33, 0xE0, 0x96, 0xF2, 0xC1, 0x91, 0x0D,
                   0x15, 0x23, 0xD3, 0x07, 0x74, 0xE7, 0x2B, 0x72,
                   0xDF, 0xA6, 0xDD, 0xE9, 0x68, 0x8B, 0x76, 0x2A,
                   0x6A, 0x87, 0x51, 0x7F, 0x85, 0x39, 0x0B, 0xD4,
                   0x20, 0x3F, 0x46, 0x89, 0x04, 0x82, 0xB7, 0x30,
                   0x84, 0x89, 0x4B, 0xCC, 0x9D, 0xB1, 0x24, 0x7C};
  u8 iv[0x10] = {0x58, 0x90, 0x37, 0x2A, 0x42, 0x71, 0x2C, 0x50,
                 0xDB, 0xA9, 0x95, 0xFF, 0xD3, 0x0F, 0xC8, 0x0C};

  memcpy (buffer, key1, 0x40);
  vtrm_decrypt_master (0x1070000002000001ULL, 0x10700005FF000001ULL,
      buffer, iv);
  hex_dump (buffer, 0x40);
  printf ("\n");
  memcpy (buffer, key2, 0x40);
  vtrm_decrypt_master (0x1070000002000001ULL, 0x10700005FF000001ULL,
      buffer, iv);
  hex_dump (buffer, 0x40);
  printf ("\n");
  memcpy (buffer, key3, 0x40);
  memcpy (iv, "_USB_DONGLE_AUTH_USB_DONGLE_", 0x10);
  vtrm_decrypt_master (0x1070000001000001ULL, 0x1070000045000001ULL,
      buffer, iv);
  hex_dump (buffer, 0x40);

}
*/
