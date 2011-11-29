// 2011 Ninjas
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt

#include "tools.h"
#include "types.h"
#include "common.h"

#include "paged_file.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>

#define PS3XPORT_VERSION "0.1"

#undef DEBUG

#ifdef DEBUG
#define DBG(format, ...) fprintf (stderr, format, ## __VA_ARGS__)
#else
#define DBG(...)
#endif

#define die(format, ...) {                              \
    fprintf (stderr, format, ## __VA_ARGS__);           \
    exit (-1);                                          \
  }


#define USAGE_STRING "PS3xport v" PS3XPORT_VERSION "\n"                 \
  "  Usage: %s command [argument ...] [command ...]\n"                  \
  "    Commands : \n"                                                   \
  "\t  SetDeviceID HEX: Set the DeviceID needed for decrypting archive2.dat\n" \
  "\t  Parse archive.dat: Parse the index file and print info\n"        \
  "\t  Decrypt archive[_XX].dat output: Decrypt the given file\n"       \
  "\t  Dump backup_dir destination: Extract the whole backup to the destination\n" \
  "\t  Add backup_dir directory: Add the given directory and subdirs to the backup\n\n" \
  "\t  TestBinary method filename: Test binary file for keys to method (0-7)\n\n"


typedef struct _ChainedList ChainedList;
struct _ChainedList {
  void *data;
  ChainedList *next;
};
typedef void (*ChainedListForeachCallback) (void *, void *);

typedef struct {
  u32 mode;
  u32 uid;
  s32 gid;
  u64 atime;
  u64 mtime;
  u64 ctime;
  u64 file_size;
  u64 block_size;
} FileStat;

typedef struct {
  union {
    char path[0x520];
    struct {
      u64 zero;
      u64 total_files;
      u64 total_file_sizes;
    } eos;
  };
  FileStat stat;
  u32 flags; /* 1 == dev_flash2 */
} ArchiveFile;

typedef struct {
  union {
    char path[0x420];
    struct {
      u64 zero;
      u64 total_dirs;
    } eos;
  };
  FileStat stat;
  u32 flags; /* 2 == dev_flash2 */
} ArchiveDirectory;

typedef struct {
  u64 id;
  u64 footer;
  u8 psid[0x10];
  ChainedList *files;
  u64 total_files;
  u64 total_file_sizes;
  ChainedList *dirs;
  u64 total_dirs;
} IndexArchive;

typedef struct {
  u32 size;
  u32 type;
  u8 hash[0x14];
  u8 key_seed[0x14];
  u8 padding[0x10];
} ArchiveHeader;

typedef struct {
  u64 id;
  u32 index;
  u8 unknown1;
  u8 unknown2;
  u16 padding;
} ArchiveEncryptedHeader;

typedef struct {
  u8 psid[0x10];
  u64 unknown;
  u64 zero;
} IndexArchiveFooter;

typedef struct {
  u64 id;
  u64 type;
  u32 index;
} DataArchive;

static u8 device_id[0x10];
static int device_id_set;

static ChainedList *
chained_list_append (ChainedList *list, void *data)
{
  ChainedList *l = malloc (sizeof(ChainedList));
  ChainedList *c;

  l->data = data;
  l->next = NULL;
  if (list == NULL)
    return l;

  c = list;
  while (c->next) c = c->next;
  c->next = l;

  return list;
}

static void
chained_list_foreach (ChainedList *list, ChainedListForeachCallback cb, void *user_data)
{
  ChainedList *current = list;

  while (current != NULL) {
    cb (current->data, user_data);
    current = current->next;
  }
}

static void
chained_list_free (ChainedList *list)
{
  ChainedList *current = list;
  ChainedList *next;

  while (current != NULL) {
    next = current->next;
    free (current);
    current = next;
  }
}

static void
generate_random_key_seed (u8 *seed)
{
  get_rand (seed, 0x14);
}

static void
sc_encrypt_with_portability (int type, u8 *buffer, u8 *iv)
{
  static u8 keys[][16] = {
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0xFA, 0x72, 0xCE, 0xEF, 0x59, 0xB4, 0xD2, 0x98,
     0x9F, 0x11, 0x19, 0x13, 0x28, 0x7F, 0x51, 0xC7},
    {0xD4, 0x13, 0xB8, 0x96, 0x63, 0xE1, 0xFE, 0x9F,
     0x75, 0x14, 0x3D, 0x3B, 0xB4, 0x56, 0x52, 0x74},
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
  };

  static u8 expected[][0x40] = {
    {0x38,0xDC,0x47,0x42,0x95,0x58,0x2B,0xD8, 0x49,0xC4,0xF4,0x5E,0xB6,0x22,0x63,0xBB,
     0xFA,0x81,0x91,0x64,0x60,0x8C,0x4F,0x9A, 0x5C,0x5A,0xC3,0x5C,0x42,0x17,0x36,0xBB,
     0x95,0x29,0x2C,0x24,0xD6,0x51,0x3E,0xB1, 0x2F,0xF8,0x85,0x04,0x73,0xB1,0x11,0xE7,
     0xCF,0x0D,0xFC,0xE3,0xB6,0xDB,0x3A,0xD4, 0xCF,0x64,0x9A,0x9A,0xBA,0xBA,0xBD,0x94},
    {0},
    {0},
    {0x38,0xDC,0x47,0x42,0x95,0x58,0x2B,0xD8, 0x49,0xC4,0xF4,0x5E,0xB6,0x22,0x63,0xBB,
     0xFA,0x81,0x91,0x64,0x60,0x8C,0x4F,0x9A, 0x5C,0x5A,0xC3,0x5C,0x42,0x17,0x36,0xBB,
     0x95,0x29,0x2C,0x24,0xD6,0x51,0x3E,0xB1, 0x2F,0xF8,0x85,0x04,0x73,0xB1,0x11,0xE7,
     0xCF,0x0D,0xFC,0xE3,0xB6,0xDB,0x3A,0xD4, 0xCF,0x64,0x9A,0x9A,0xBA,0xBA,0xBD,0x94},
  };

  printf ("encrypt_with_portability type=%d\n", type);

  switch ( type )
  {
    case 0:
      memcpy (buffer, expected[type], 0x40);
      //aes128cbc_enc (keys[type], iv, buffer, 0x40, buffer);
      break;
    case 1:
      aes128cbc_enc (keys[type], iv, buffer, 0x40, buffer);
      break;
    case 2:
      aes128cbc_enc (keys[type], iv, buffer, 0x40, buffer);
      break;
    case 3:
      memcpy (buffer, expected[type], 0x40);
      //aes128cbc_enc (keys[type], iv, buffer, 0x40, buffer);
      break;
  }

  return;
}

static void
sc_encrypt (int type, u8 *buffer, u8 *iv)
{
  static u8 keys[][16] = {
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
  };

  static u8 expected[][0x40] = {
    {0x0B,0xCF,0x9D,0x06,0x47,0x6D,0x59,0x6F, 0x85,0xD4,0x1F,0xD9,0x4B,0xBA,0x60,0x58,
     0xFC,0xAD,0x5A,0xBF,0xC6,0x53,0x47,0xE1, 0xE3,0x79,0x24,0x43,0x18,0xAF,0x3B,0xCC,
     0x0D,0x1E,0xEA,0xA0,0xA3,0x3F,0x98,0x52, 0x8C,0x35,0xB1,0x25,0x12,0xB6,0x3A,0x36,
     0xAF,0x73,0xBA,0x7C,0x43,0x4B,0x24,0xEB, 0x25,0x86,0x64,0x3D,0x70,0x8F,0x0D,0x71},
 
    {0x19,0x30,0x37,0xFA,0x8F,0x48,0xB6,0x6B, 0x80,0x8B,0xAE,0x92,0xCB,0x0D,0xB4,0x4D,
     0x18,0xF6,0xF9,0x79,0xC1,0xDF,0x71,0xAF, 0x68,0x77,0xBC,0x36,0x35,0x75,0x56,0x4F,
     0x59,0x11,0x09,0x64,0xB7,0x4A,0xE1,0x4C, 0x98,0x38,0x06,0xDE,0x17,0x54,0x84,0x52,
     0x00,0xB4,0x75,0xDE,0xA0,0xDC,0xCB,0xCF, 0x4B,0x38,0x7B,0x31,0x43,0xEF,0xC7,0x1F},
 
    {0x30,0x2E,0xDA,0xF2,0xAB,0xCA,0xD4,0x84, 0x59,0x0B,0x04,0x24,0x77,0x1D,0x1C,0x9F,
     0xB4,0xD2,0x73,0x54,0xD3,0xB3,0x04,0xED, 0x5A,0x68,0xB6,0xFB,0x02,0xA4,0x68,0x78,
     0xF9,0xDC,0x4B,0xFD,0x6B,0xA9,0x8A,0x28, 0x12,0x6B,0x2B,0x32,0x9C,0x1F,0x08,0x80,
     0xF5,0x71,0xC6,0xD4,0x69,0x3D,0xDE,0x25, 0x70,0x3F,0x21,0xB7,0x89,0x7C,0xDC,0x25},
 
    {0x61,0x83,0xD6,0xAE,0xD0,0x41,0xE9,0x48, 0xEF,0xD8,0x35,0xE4,0x00,0xCE,0x79,0x0F,
     0x58,0xAB,0xE7,0x8C,0xC2,0x7E,0x62,0x0B, 0xA2,0xAC,0x77,0xCF,0xEB,0x86,0xA3,0x32,
     0x16,0xAC,0x3B,0xDC,0xE6,0x32,0x75,0x75, 0xBB,0xCC,0xEE,0x81,0xE7,0x0C,0xBB,0x79,
     0x9F,0x88,0xFB,0x3C,0x68,0x9A,0x2D,0x88, 0xFB,0x69,0x6F,0xC8,0x58,0x96,0x94,0xBE},
  };

  printf ("encrypt type=%d\n", type);

  switch ( type )
  {
    case 0:
      memcpy (buffer, expected[type], 0x40);
      //aes128cbc_enc (keys[type], iv, buffer, 0x40, buffer);
      break;
    case 1:
      memcpy (buffer, expected[type], 0x40);
      //aes128cbc_enc (keys[type], iv, buffer, 0x40, buffer);
      break;
    case 2:
      memcpy (buffer, expected[type], 0x40);
      //aes128cbc_enc (keys[type], iv, buffer, 0x40, buffer);
      break;
    case 3:
      memcpy (buffer, expected[type], 0x40);
      //aes128cbc_enc (keys[type], iv, buffer, 0x40, buffer);
      break;
  }

  return;
}

static int
archive_gen_keys (ArchiveHeader *header, u8 *key, u8 *iv, u8 *hmac)
{
  u8 buffer[0x40];
  u8 zero_iv[0x10];

  memset (buffer, 0, 0x40);
  memset (zero_iv, 0, 0x10);
  if (header->size == 0x30) {
    if (!device_id_set)
      die ("Device ID is not set. You must set it with the command SetDeviceID\n");
    memcpy (buffer, device_id, 0x10);
    sc_encrypt (3, buffer, zero_iv);
  } else {
    memcpy (buffer, header->key_seed, 0x14);
    sc_encrypt_with_portability (1, buffer, zero_iv);
  }
  memcpy (key, buffer, 0x10);
  memcpy (iv, buffer + 0x10, 0x10);
  memset (hmac, 0, 0x40);
  memcpy (hmac, buffer + 0x2C, 0x14);

  return TRUE;
}

static int
archive_open (const char *path, PagedFile *file, ArchiveHeader *header)
{
  u8 key[0x10];
  u8 iv[0x10];
  u8 hmac[0x40];


  if (!paged_file_open (file, path, TRUE)) {
    DBG ("Couldn't open file %s\n", path);
    goto end;
  }

  if (paged_file_read (file, header, sizeof(ArchiveHeader)) != sizeof(ArchiveHeader)) {
    DBG ("Couldn't read file header\n");
    goto end;
  }

  header->size = FROM_LE (32, header->size);
  header->type = FROM_BE (32, header->type);

  if (header->size != 0x40 && header->size != 0x30) {
    DBG ("Invalid header size : %X\n", header->size);
    goto end;
  }

  if (header->type != 5) {
    DBG ("Header type must be 5, not : %X\n", header->type);
    goto end;
  }

  if (!archive_gen_keys (header, key, iv, hmac)) {
    DBG ("Error generating keys\n");
    goto end;
  }

  paged_file_hash (file, hmac);
  paged_file_crypt (file, key, iv);

  return TRUE;
 end:
  paged_file_close (file);
  return FALSE;
}

static int
archive_decrypt (const char *path, const char *to)
{
  FILE *fd = NULL;
  ArchiveHeader header;
  PagedFile file = {0};
  int read;
  int ret = FALSE;

  if (!archive_open (path, &file, &header)) {
    DBG ("Couldn't open file %s\n", path);
    goto end;
  }

  fd = fopen (to, "wb");
  if (!fd) {
    DBG ("Couldn't open output file %s\n", to);
    goto end;
  }

  header.size = TO_LE (32, header.size);
  header.type = TO_BE (32, header.type);
  fwrite (&header, sizeof(header), 1, fd);

  do {
    u8 buffer[1024];
    read = paged_file_read (&file, buffer, sizeof(buffer));
    fwrite (buffer, read, 1, fd);
  } while (read > 0);


  ret = TRUE;
 end:
  if (fd)
    fclose (fd);

  paged_file_close (&file);

  if (ret && memcmp (header.hash, file.digest, 0x14) != 0) {
    DBG ("HMAC hash does not match\n");
    ret = FALSE;
  }
  return ret;
}

static int
index_archive_read (IndexArchive *archive, const char *path)
{
  PagedFile file = {0};
  ArchiveHeader header;
  ArchiveEncryptedHeader header2;
  IndexArchiveFooter footer;

  archive->id = archive->footer = 0;
  archive->files = archive->dirs = NULL;
  archive->total_files = archive->total_file_sizes = archive->total_dirs = 0;

  if (!archive_open (path, &file, &header)) {
    DBG ("Couldn't open file %s\n", path);
    goto end;
  }

  if (paged_file_read (&file, &header2, sizeof(header2)) != sizeof(header2)) {
    DBG ("Couldn't read encrypted header\n");
    goto end;
  }
  header2.index = FROM_BE (32, header2.index);
  archive->id = header2.id;

  while(1) {
    ArchiveFile *archive_file = malloc (sizeof(ArchiveFile));
    if (paged_file_read (&file, archive_file, sizeof(ArchiveFile)) != sizeof(ArchiveFile)) {
      DBG ("Couldn't read file entry\n");
      goto end;
    }
    if (archive_file->eos.zero == 0) {
      archive->total_files = FROM_BE (64, archive_file->eos.total_files);
      archive->total_file_sizes = FROM_BE (64, archive_file->eos.total_file_sizes);
      free (archive_file);
      break;
    }
    archive_file->stat.mode = FROM_BE (32, archive_file->stat.mode);
    archive_file->stat.uid = FROM_BE (32, archive_file->stat.uid);
    archive_file->stat.gid = FROM_BE (32, archive_file->stat.gid);
    archive_file->stat.atime = FROM_BE (64, archive_file->stat.atime);
    archive_file->stat.mtime = FROM_BE (64, archive_file->stat.mtime);
    archive_file->stat.ctime = FROM_BE (64, archive_file->stat.ctime);
    archive_file->stat.file_size = FROM_BE (64, archive_file->stat.file_size);
    archive_file->stat.block_size = FROM_BE (64, archive_file->stat.block_size);
    archive_file->flags = FROM_BE (32, archive_file->flags);
    archive->files = chained_list_append (archive->files, archive_file);
    DBG ("File : %s\n", archive_file->path);
  }
  while(1) {
    ArchiveDirectory *archive_dir = malloc (sizeof(ArchiveDirectory));
    if (paged_file_read (&file, archive_dir, sizeof(ArchiveDirectory)) != sizeof(ArchiveDirectory)) {
      DBG ("Couldn't read directory entry\n");
      goto end;
    }
    if (archive_dir->eos.zero == 0) {
      archive->total_dirs = FROM_BE (64, archive_dir->eos.total_dirs);
      free (archive_dir);
      break;
    }
    archive_dir->stat.mode = FROM_BE (32, archive_dir->stat.mode);
    archive_dir->stat.uid = FROM_BE (32, archive_dir->stat.uid);
    archive_dir->stat.gid = FROM_BE (32, archive_dir->stat.gid);
    archive_dir->stat.atime = FROM_BE (64, archive_dir->stat.atime);
    archive_dir->stat.mtime = FROM_BE (64, archive_dir->stat.mtime);
    archive_dir->stat.ctime = FROM_BE (64, archive_dir->stat.ctime);
    archive_dir->stat.file_size = FROM_BE (64, archive_dir->stat.file_size);
    archive_dir->stat.block_size = FROM_BE (64, archive_dir->stat.block_size);
    archive_dir->flags = FROM_BE (32, archive_dir->flags);
    archive->dirs = chained_list_append (archive->dirs, archive_dir);
    DBG ("Directory : %s\n", archive_dir->path);
  }

  if (header2.unknown1 == 5) {
    if (paged_file_read (&file, &footer, sizeof(footer)) != sizeof(footer)) {
      DBG ("Couldn't read footer\n");
      goto end;
    }
    memcpy (archive->psid, footer.psid, 0x10);
    archive->footer = footer.unknown;
  }

  paged_file_close (&file);

  if (memcmp (header.hash, file.digest, 0x14) != 0) {
    DBG ("HMAC hash does not match\n");
    return FALSE;
  }

  return TRUE;

 end:
  paged_file_close (&file);
  return FALSE;
}


static int
index_archive_write (IndexArchive *archive, const char *path)
{
  FILE *fd = NULL;
  PagedFile file = {0};
  ArchiveHeader header;
  ArchiveEncryptedHeader header2;
  IndexArchiveFooter footer;
  ArchiveFile file_eos = {0};
  ArchiveDirectory dir_eos = {0};
  ChainedList *list;
  u8 key[0x10];
  u8 iv[0x10];
  u8 hmac[0x40];

  if (!paged_file_open (&file, path, FALSE)) {
    DBG ("Couldn't open file %s\n", path);
    goto end;
  }

  header.size = TO_LE (32, 0x40);
  header.type = TO_BE (32, 0x05);
  generate_random_key_seed (header.key_seed);
  memset (header.padding, 0, 0x10);

  if (paged_file_write (&file, &header, sizeof(header)) != sizeof(header)) {
    DBG ("Couldn't write file header\n");
    goto end;
  }

  if (!archive_gen_keys (&header, key, iv, hmac)) {
    DBG ("Error generating keys\n");
    goto end;
  }

  paged_file_flush (&file);
  paged_file_hash (&file, hmac);
  paged_file_crypt (&file, key, iv);

  header2.id = archive->id;
  header2.index = 0;
  header2.unknown1 = 5;
  header2.unknown2 = 1;
  header2.padding = 0;
  if (paged_file_write (&file, &header2, sizeof(header2)) != sizeof(header2)) {
    DBG ("Couldn't write encrypted header\n");
    goto end;
  }

  archive->total_files = 0;
  archive->total_file_sizes = 0;
  for (list = archive->files; list; list = list->next) {
    ArchiveFile *archive_file = list->data;

    archive->total_files++;
    archive->total_file_sizes += archive_file->stat.file_size;
    archive_file->stat.mode = TO_BE (32, archive_file->stat.mode);
    archive_file->stat.uid = TO_BE (32, archive_file->stat.uid);
    archive_file->stat.gid = TO_BE (32, archive_file->stat.gid);
    archive_file->stat.atime = TO_BE (64, archive_file->stat.atime);
    archive_file->stat.mtime = TO_BE (64, archive_file->stat.mtime);
    archive_file->stat.ctime = TO_BE (64, archive_file->stat.ctime);
    archive_file->stat.file_size = TO_BE (64, archive_file->stat.file_size);
    archive_file->stat.block_size = TO_BE (64, archive_file->stat.block_size);
    archive_file->flags = TO_BE (32, archive_file->flags);
    if (paged_file_write (&file, archive_file, sizeof(ArchiveFile)) != sizeof(ArchiveFile)) {
      DBG ("Couldn't write file entry\n");
      goto end;
    }
  }
  file_eos.eos.zero = 0;
  file_eos.eos.total_files = TO_BE (64, archive->total_files);
  file_eos.eos.total_file_sizes = TO_BE (64, archive->total_file_sizes);
  if (paged_file_write (&file, &file_eos, sizeof(ArchiveFile)) != sizeof(ArchiveFile)) {
    DBG ("Couldn't write file EOS\n");
    goto end;
  }
  archive->total_dirs = 0;
  for (list = archive->dirs; list; list = list->next) {
    ArchiveDirectory *archive_dir = list->data;

    archive->total_dirs++;
    archive_dir->stat.mode = TO_BE (32, archive_dir->stat.mode);
    archive_dir->stat.uid = TO_BE (32, archive_dir->stat.uid);
    archive_dir->stat.gid = TO_BE (32, archive_dir->stat.gid);
    archive_dir->stat.atime = TO_BE (64, archive_dir->stat.atime);
    archive_dir->stat.mtime = TO_BE (64, archive_dir->stat.mtime);
    archive_dir->stat.ctime = TO_BE (64, archive_dir->stat.ctime);
    archive_dir->stat.file_size = TO_BE (64, archive_dir->stat.file_size);
    archive_dir->stat.block_size = TO_BE (64, archive_dir->stat.block_size);
    archive_dir->flags = TO_BE (32, archive_dir->flags);
    if (paged_file_write (&file, archive_dir, sizeof(ArchiveDirectory)) != sizeof(ArchiveDirectory)) {
      DBG ("Couldn't write dir entry\n");
      goto end;
    }
  }
  dir_eos.eos.zero = 0;
  dir_eos.eos.total_dirs = TO_BE (64, archive->total_dirs);
  if (paged_file_write (&file, &dir_eos, sizeof(ArchiveDirectory)) != sizeof(ArchiveDirectory)) {
    DBG ("Couldn't write dir EOS\n");
    goto end;
  }

  if (header2.unknown1 == 5) {
    memcpy (footer.psid, archive->psid, 0x10);
    footer.unknown = archive->footer;
    footer.zero = 0;
    if (paged_file_write (&file, &footer, sizeof(footer)) != sizeof(footer)) {
      DBG ("Couldn't write footer\n");
      goto end;
    }
  }

  paged_file_flush (&file);
  fd = file.fd;
  file.fd = NULL;
  paged_file_close (&file);

  fseek (fd, 8, SEEK_SET);
  fwrite (file.digest, 0x14, 1, fd);
  fclose (fd);


  return TRUE;

 end:
  paged_file_close (&file);
  return FALSE;
}

static int
archive_dump (const char *path, const char *output)
{
  ChainedList *list = NULL;
  char buffer[0x10000];
  IndexArchive archive;
  ArchiveHeader header;
  ArchiveEncryptedHeader header2;
  PagedFile pf = {0};
  u32 index = 0;
  int open = FALSE;

  snprintf (buffer, sizeof(buffer), "%s/archive.dat", path);
  if (!index_archive_read (&archive, buffer))
    die ("Unable to read index archive\n");

  for (list = archive.dirs; list; list = list->next) {
    ArchiveDirectory *dir = list->data;

    snprintf (buffer, sizeof(buffer), "%s/%s", output, dir->path);
    if (mkdir_recursive (buffer) != 0)
      die ("Error making directories\n");
  }

  for (list = archive.files; list; list = list->next) {
    ArchiveFile *file = list->data;
    FILE *fd;
    u64 len = file->stat.file_size;

    snprintf (buffer, sizeof(buffer), "%s/%s", output, file->path);
    fd = fopen (buffer, "wb");
    if (!fd)
      die ("Error opening output file %s\n", buffer);
    while (len > 0) {
      int read;
      u32 size = len;

      if (!open) {
        snprintf (buffer, sizeof(buffer), "%s/archive_%02d.dat", path, index);
        if (!archive_open (buffer, &pf, &header)) {
          die ("Couldn't open archive %d\n", index);
        }

        if (paged_file_read (&pf, &header2, sizeof(header2)) != sizeof(header2))
          die ("Couldn't read header\n");
        if (header2.id != archive.id)
          die ("Wrong archive ID\n");
        if (FROM_BE (32, header2.index) != index)
          die ("Wrong archive index\n");
        index++;
        open = TRUE;
      }

      if (size > sizeof(buffer))
        size = sizeof(buffer);
      read = paged_file_read (&pf, buffer, size);
      if (read == 0) {
        paged_file_close (&pf);
        open = FALSE;
        continue;
      }
      fwrite (buffer, read, 1, fd);
      len -= read;
    }
    fclose (fd);
  }
  return TRUE;
}


static int
chained_list_contains_string (ChainedList *list, const char *string)
{
  ChainedList *current = list;

  while (current != NULL) {
    if (strcmp (current->data, string) == 0)
      return 1;
    current = current->next;
  }

  return 0;
}

static void
populate_dirlist (ChainedList **dirs, ChainedList **files,
    const char *base, const char *subdir, DIR *fd)
{
  struct dirent *dirent = NULL;
  struct stat stat_buf;
  char path[1024];

  while (1) {
    dirent = readdir (fd);
    if (!dirent)
      break;
    if (strcmp (dirent->d_name, ".") == 0 ||
        strcmp (dirent->d_name, "..") == 0)
      continue;
    printf ("Found %s : %s/%s\n", dirent->d_type == DT_DIR ? "directory" : "file" ,
        subdir, dirent->d_name);
    if (dirent->d_type == DT_DIR) {
      ArchiveDirectory *archive_dir = malloc (sizeof(ArchiveDirectory));
      DIR *dir_fd = NULL;

      snprintf (path, sizeof(path), "%s/%s/%s", base, subdir, dirent->d_name);
      snprintf (archive_dir->path, sizeof(archive_dir->path), "%s/%s",
          subdir, dirent->d_name);
      stat (path, &stat_buf);
      archive_dir->stat.mode = 0x41c0;
      archive_dir->stat.uid = 0;
      archive_dir->stat.gid = -1;
      archive_dir->stat.atime = stat_buf.st_atime;
      archive_dir->stat.mtime = stat_buf.st_mtime;
      archive_dir->stat.ctime = stat_buf.st_ctime;
      archive_dir->stat.file_size = 0x200;
      archive_dir->stat.block_size = 0x200;
      archive_dir->flags = 1;
      *dirs = chained_list_append (*dirs, archive_dir);

      dir_fd = opendir(path);
      if (!dir_fd)
        die ("Unable to open subdir\n");
      populate_dirlist (dirs, files, base, archive_dir->path, dir_fd);
      closedir (dir_fd);
    } else {
      ArchiveFile *archive_file = malloc (sizeof(ArchiveFile));

      snprintf (path, sizeof(path), "%s/%s/%s", base, subdir, dirent->d_name);
      stat (path, &stat_buf);
      snprintf (archive_file->path, sizeof(archive_file->path), "%s/%s",
          subdir, dirent->d_name);
      archive_file->stat.mode = 0x8180;
      archive_file->stat.uid = 0;
      archive_file->stat.gid = -1;
      archive_file->stat.atime = stat_buf.st_atime;
      archive_file->stat.mtime = stat_buf.st_mtime;
      archive_file->stat.ctime = stat_buf.st_ctime;
      archive_file->stat.file_size = stat_buf.st_size;
      archive_file->stat.block_size = 0x200;
      archive_file->flags = 0;
      *files = chained_list_append (*files, archive_file);
    }
  }
}

static int
archive_add (const char *path, const char *game)
{
  ChainedList *list = NULL;
  char buffer[0x10000];
  IndexArchive archive;
  ArchiveHeader header;
  ArchiveEncryptedHeader header2;
  ChainedList *dirs = NULL;
  ChainedList *files = NULL;
  PagedFile in = {0};
  PagedFile out = {0};
  u32 index = 0;
  int open = FALSE;
  FILE *fd = NULL;
  DIR *dir_fd = NULL;
  u32 total_file_size = 0;
  u8 key[0x10];
  u8 iv[0x10];
  u8 hmac[0x40];

  dir_fd = opendir(game);
  if (!dir_fd)
    die ("Unable to open game dir\n");

  populate_dirlist (&dirs, &files, game, "", dir_fd);
  closedir (dir_fd);

  snprintf (buffer, sizeof(buffer), "%s/archive.dat", path);
  if (!index_archive_read (&archive, buffer))
    die ("Unable to read index archive\n");

  for (list = dirs; list; list = list->next) {
    ArchiveDirectory *dir = list->data;

    if (strcmp (dir->path, "/dev_hdd0") == 0 ||
        chained_list_contains_string (archive.dirs, dir->path)) {
      free (dir);
      continue;
    }
    archive.dirs = chained_list_append (archive.dirs, dir);
  }
  chained_list_free (dirs);

  /* TODO : try to write to a different file instead of appending to an existing one */
  while (1) {
    snprintf (buffer, sizeof(buffer), "%s/archive_%02d.dat", path, index);
    if (!file_exists (buffer)) {
      if (index == 0)
        break;
      index--;
      break;
    }
    index++;
  }

  if (!archive_open (buffer, &in, &header))
    die ("Couldn't open archive %d\n", index);

  if (paged_file_read (&in, &header2, sizeof(header2)) != sizeof(header2))
    die ("Couldn't read header\n");
  if (header2.id != archive.id)
    die ("Wrong archive ID\n");
  if (FROM_BE (32, header2.index) != index)
    die ("Wrong archive index\n");
  snprintf (buffer, sizeof(buffer), "%s/archive_%02d.tmp", path, index);
  if (!paged_file_open (&out, buffer, FALSE))
    die ("Couldn't open output archive %d\n", index);

  header.size = TO_LE (32, header.size);
  header.type = TO_BE (32, header.type);
  if (paged_file_write (&out, &header, sizeof(header)) != sizeof(header))
    die ("Couldn't write file header\n");
  total_file_size += sizeof(header);

  if (!archive_gen_keys (&header, key, iv, hmac))
    die ("Error generating keys\n");

  paged_file_flush (&out);
  paged_file_hash (&out, hmac);
  paged_file_crypt (&out, key, iv);

  if (paged_file_write (&out, &header2, sizeof(header2)) != sizeof(header2))
    die ("Couldn't write encrypted header\n");
  total_file_size += sizeof(header2);

  while (1) {
    int read = paged_file_read (&in, buffer, sizeof(buffer));
    if (read == 0)
      break;
    if (total_file_size + read > 0xFFFFFE00)
      die ("Output file is too big\n");
    paged_file_write (&out, buffer, read);
    total_file_size += read;
  }
  paged_file_close (&in);

  for (list = files; list; list = list->next) {
    ArchiveFile *file = list->data;

    if (chained_list_contains_string (archive.files, file->path)) {
      free (file);
      continue;
    }

    snprintf (buffer, 0x500, "%s/%s", game, file->path);
    fd = fopen (buffer, "rb");
    if (!fd)
      die ("Couldn't open input file : %s\n", buffer);

    while (1) {
      int read = fread (buffer, 1, sizeof(buffer), fd);
      if (read == 0)
        break;
      /* TODO : Must be able to exceed a file size of 0xFFFFFE00 by splitting */
      if (total_file_size + read > 0xFFFFFE00)
        die ("Output file is too big\n");
      paged_file_write (&out, buffer, read);
      total_file_size += read;
    }

    fclose (fd);
    archive.files = chained_list_append (archive.files, file);
  }
  paged_file_flush (&out);
  fd = out.fd;
  out.fd = NULL;
  paged_file_close (&out);

  fseek (fd, 8, SEEK_SET);
  fwrite (out.digest, 0x14, 1, fd);
  fclose (fd);


  snprintf (buffer, 0x500, "%s/archive_%02d.bak", path, index);
  snprintf (buffer + 0x500, 0x500, "%s/archive_%02d.dat", path, index);
  if (rename (buffer + 0x500, buffer) != 0)
    die ("File rename failed\n");
  snprintf (buffer, 0x500, "%s/archive_%02d.tmp", path, index);
  if (rename (buffer, buffer + 0x500) != 0)
    die ("File rename failed\n");
  snprintf (buffer, 0x500, "%s/archive.dat", path, index);
  snprintf (buffer + 0x500, 0x500, "%s/archive.bak", path, index);
  if (rename (buffer, buffer + 0x500) != 0)
    die ("File rename failed\n");

  snprintf (buffer, sizeof(buffer), "%s/archive.dat", path);
  if (!index_archive_write (&archive, buffer))
    die ("Unable to write index archive\n");

  return TRUE;
}

static void
archive_print_dir (ArchiveDirectory *dir, char *prefix)
{
  printf ("%s%s\n", prefix, dir->path);
}
static void
archive_print_file (ArchiveFile *file, char *prefix)
{
  printf ("%s%s\n", prefix, file->path);
}

int
main (int argc, char *argv[])
{
  int i;

  if (argc < 2)
    die (USAGE_STRING, argv[0]);

  for (i = 1; i < argc; i++) {
    if (strcmp (argv[i], "Decrypt") == 0) {
      if (i + 2 >= argc)
        die (USAGE_STRING "Not enough arguments to command\n", argv[0]);
      if (!archive_decrypt (argv[i+1], argv[i+2]))
        die ("Error decrypting archive!\n");
      i += 2;
    } else if (strcmp (argv[i], "Parse") == 0) {
      IndexArchive archive;

      if (i + 1 >= argc)
        die (USAGE_STRING "Not enough arguments to command\n", argv[0]);
      i++;
      if (!index_archive_read (&archive, argv[i]))
        die ("Error parsing archive!\n");
      printf ("Backup id : ");
      print_hash ((u8 *) &archive.id, 8);
      printf ("\nFooter : ");
      print_hash ((u8 *) &archive.footer, 8);
      printf ("\nYour Open PSID : ");
      print_hash (archive.psid, 16);
      printf ("\nTotal directories : %llu\n", archive.total_dirs);
      chained_list_foreach (archive.dirs,
          (ChainedListForeachCallback) archive_print_dir, (void *) "    ");
      printf ("\nTotal files : %llu\n", archive.total_files);
      chained_list_foreach (archive.files,
          (ChainedListForeachCallback) archive_print_file, (void *) "    ");
      printf ("\nTotal archive size : %llu bytes\n", archive.total_file_sizes);
    } else if (strcmp (argv[i], "Dump") == 0) {
      if (i + 2 >= argc)
        die (USAGE_STRING "Not enough arguments to command\n", argv[0]);
      if (!archive_dump (argv[i+1], argv[i+2]))
        die ("Error dumping backup!\n");
      i += 2;
    } else if (strcmp (argv[i], "Add") == 0) {
      if (i + 2 >= argc)
        die (USAGE_STRING "Not enough arguments to command\n", argv[0]);
      if (!archive_add (argv[i+1], argv[i+2]))
        die ("Error adding directory to backup!\n");
      i += 2;
    } else if (strcmp (argv[i], "SetDeviceID") == 0) {
      int j;

      if (i + 1 >= argc)
        die (USAGE_STRING "Not enough arguments to command\n", argv[0]);
      i++;
      if (strlen (argv[i]) != 32)
        die ("Device ID must be 16 bytes and in hex format\n");
      for (j = 0; j < 32; j += 2) {
        char tmp[3] = {0};
        memcpy (tmp, argv[i] + j, 2);
        if (sscanf (tmp, "%X", device_id + (j/2) ) != 1)
          die ("Device ID must be in hex format\n");
      }
      device_id_set = TRUE;
      printf ("Device ID set to : ");
      print_hash (device_id, 16);
      printf ("\n");
    } else if (strcmp (argv[i], "TestBinary") == 0) {
      FILE *in;
      u8 *data;
      unsigned int len;
      unsigned int j;
      int type;

      if (i + 2 >= argc)
        die (USAGE_STRING "Not enough arguments to command\n", argv[0]);

      if (argv[i+1][1] != 0)
        die ("Method must be between 0 and 7\n");
      type = argv[i+1][0] - '0';
      if (type < 0 || type > 7)
        die ("Method must be between 0 and 7\n");

      in = fopen (argv[i+2], "rb");
      if (in == NULL)
        die ("Unable to open %s", argv[i+2]);
      fseek (in, 0, SEEK_END);
      len = ftell (in);
      fseek (in, 0, SEEK_SET);
      data = malloc (len);

      if (fread (data, 1, len, in) != len)
        die ("Unable to read index.dat file");
      fclose (in);
      i += 2;
      {
        u8 seed[0x14] = {0};
        u8 iv[0x10] = {0};
        u8 key[0x40] = {0};
        u8 expected[0x40];
        u8 input[0x40] = {0};
        u8 output[0x40];

        memset (expected, 0, 0x40);
        memset (output, 0, 0x40);
        memset (input, 0, 0x40);
        memset (key, 0, 0x40);
        memset (iv, 0, 0x10);

        printf("\n");

        switch (type) {
          case 0:
            sc_encrypt_with_portability (0, expected, iv);
            break;
          case 1:
            sc_encrypt_with_portability (1, expected, iv);
            break;
          case 2:
            sc_encrypt_with_portability (2, expected, iv);
            break;
          case 3:
            sc_encrypt_with_portability (3, expected, iv);
            break;
          case 4:
            sc_encrypt (0, expected, iv);
            break;
          case 5:
            sc_encrypt (1, expected, iv);
            break;
          case 6:
            sc_encrypt (2, expected, iv);
            break;
          case 7:
            sc_encrypt (3, expected, iv);
            break;
          default:
            die ("Method must be between 0 and 7\n");
        }

        //hex_dump (expected, 0x40);

        for (j = 0; j < len - 0x10; j++) {
          memset (output, 0, 0x40);
          memset (input, 0, 0x40);
          memset (key, 0, 0x40);
          memset (iv, 0, 0x10);
          memcpy (key, data + j, 0x40);
          //aes256cbc_enc (data + j, iv, input, 0x40, output);
          aes256cbc_enc (key, iv, input, 0x40, output);
          if (memcmp (expected, output, 0x40) == 0) {
            printf ("\nFound the key for method %s %d\n",
                type < 4 ? "sc_encrypt_with_portability" : "sc_encrypt", type);
            printf ("aes256cbc_enc key:\n");
            hex_dump (data + j, 0x10);
/*
            printf ("expected:\n");
            hex_dump (expected, 0x40);
            printf ("output:\n");
            hex_dump (output, 0x40);
*/
            printf ("\n");
            break;
          }

          memset (output, 0, 0x40);
          memset (input, 0, 0x40);
          memset (key, 0, 0x40);
          memset (iv, 0, 0x10);
          memcpy (key, data + j, 0x40);
          //aes128ctr (data + j, iv, input, 0x40, output);
          aes128ctr (key, iv, input, 0x40, output);
          if (memcmp (expected, output, 0x40) == 0) {
            printf ("\nFound the key for method %s %d\n",
                type < 4 ? "sc_encrypt_with_portability" : "sc_encrypt", type);
            printf ("aes128ctr key:\n");
            hex_dump (data + j, 0x10);
/*
            printf ("expected:\n");
            hex_dump (expected, 0x40);
            printf ("output:\n");
            hex_dump (output, 0x40);
*/
            printf ("\n");
            break;
          }

          memset (output, 0, 0x40);
          memset (input, 0, 0x40);
          memset (key, 0, 0x40);
          memset (iv, 0, 0x10);
          memcpy (key, data + j, 0x40);
          //aes128cfb (data + j, iv, input, 0x40, output);
          aes128cfb (key, iv, input, 0x40, output);
          if (memcmp (expected, output, 0x40) == 0) {
            printf ("\nFound the key for method %s %d\n",
                type < 4 ? "sc_encrypt_with_portability" : "sc_encrypt", type);
            printf ("aes128cfb key:\n");
            hex_dump (data + j, 0x10);
/*
            printf ("expected:\n");
            hex_dump (expected, 0x40);
            printf ("output:\n");
            hex_dump (output, 0x40);
*/
            printf ("\n");
            break;
          }

          memset (output, 0, 0x40);
          memset (input, 0, 0x40);
          memset (key, 0, 0x40);
          memset (iv, 0, 0x10);
          memcpy (key, data + j, 0x40);
          //aes128cbc_enc (data + j, iv, input, 0x40, output);
          aes128cbc_enc (key, iv, input, 0x40, output);
          if (memcmp (expected, output, 0x40) == 0) {
            printf ("\nFound the key for method %s %d\n",
                type < 4 ? "sc_encrypt_with_portability" : "sc_encrypt", type);
            printf ("aes128cbc_enc key:\n");
            hex_dump (data + j, 0x10);
/*
            printf ("expected:\n");
            hex_dump (expected, 0x40);
            printf ("output:\n");
            hex_dump (output, 0x40);
*/
            printf ("\n");
            break;
          }
        }
        printf("\n");
        free (data);
      }
    } else {
      die (USAGE_STRING "Error: Unknown command\n", argv[0]);
    }
  }

  return 0;
}

