/*

Copyright 2015 Kakaroto

This software is distributed under the terms of the GNU General Public
License ("GPL") version 3, as published by the Free Software Foundation.

*/

#define  __USE_FILE_OFFSET64
#define __USE_LARGEFILE64

#include "tools.h"
#include "types.h"
#include "common.h"

#include "paged_file.h"
#include "archive.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>

#ifdef _WIN32
#undef stat
#define stat _stat64
#endif

static u8 device_id[0x10] = {0};
static int device_id_set = FALSE;
static u8 open_psid[0x10] = {0};
static int open_psid_set = FALSE;

ChainedList *
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

void
chained_list_foreach (ChainedList *list, ChainedListForeachCallback cb, void *user_data)
{
  ChainedList *current = list;

  while (current != NULL) {
    cb (current->data, user_data);
    current = current->next;
  }
}

void
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

/*

The archive is encrypted and we need to generate the keys by either
using the device ID (IDP) or the key seed in the archive header

*/

static int
archive_gen_keys (DatFileHeader *header, u8 *key, u8 *iv, u8 *hmac)
{
  u8 buffer[0x40];
  u8 zero_iv[0x10];

  memset (buffer, 0, 0x40);
  memset (zero_iv, 0, 0x10);
  if (header->encryption_type == ENCRYPTION_TYPE_IDP) {
    if (!device_id_set)
      die ("Device ID is not set. You must set it with the command SetDeviceID\n");
    memcpy (buffer, device_id, 0x10);
    vtrm_encrypt (3, buffer, zero_iv);
  } else {
    memcpy (buffer, header->key_seed, 0x14);
    vtrm_encrypt_with_portability (1, buffer, zero_iv);
  }
  memcpy (key, buffer, 0x10);
  memcpy (iv, buffer + 0x10, 0x10);
  memset (hmac, 0, 0x40);
  memcpy (hmac, buffer + 0x2C, 0x14);

  return TRUE;
}

int
archive_open (const char *path, PagedFile *file, DatFileHeader *dat_header)
{
  u8 key[0x10];
  u8 iv[0x10];
  u8 hmac[0x40];


  if (!paged_file_open (file, path, TRUE)) {
    DBG ("Couldn't open file %s\n", path);
    goto end;
  }

  if (paged_file_read (file, dat_header, sizeof(DatFileHeader)) != sizeof(DatFileHeader)) {
    DBG ("Couldn't read dat file header\n");
    goto end;
  }
  ARCHIVE_DAT_FILE_HEADER_FROM_BE (*dat_header);

  /* Encryption type is either 0x40 (includes a key seed) or 0x30 (uses IDP as key seed) */
  
  if (dat_header->encryption_type != ENCRYPTION_TYPE_KEYSEED &&
      dat_header->encryption_type != ENCRYPTION_TYPE_IDP) {
    DBG ("Invalid dat encryption type : %X\n", dat_header->encryption_type);
    goto end;
  }

  if (dat_header->dat_type != DAT_TYPE_WITH_PROTECTED_ARCHIVE &&
      dat_header->dat_type != DAT_TYPE_NO_PROTECTED_ARCHIVE) {
    DBG ("Header type must be 5 or 3, not : %X\n", dat_header->dat_type);
    goto end;
  }

  if (!archive_gen_keys (dat_header, key, iv, hmac)) {
    DBG ("Error generating keys\n");
    goto end;
  }

  paged_file_hash (file, hmac);
  paged_file_crypt (file, key, iv, PAGED_FILE_CRYPT_AES_128_CBC, NULL, NULL);

  return TRUE;
 end:
  paged_file_close (file);
  return FALSE;
}

int
archive_decrypt (const char *path, const char *to)
{
  FILE *fd = NULL;
  DatFileHeader dat_header;
  PagedFile file = {0};
  int read;
  int ret = FALSE;

  if (!archive_open (path, &file, &dat_header)) {
    DBG ("Couldn't open file %s\n", path);
    goto end;
  }

  fd = fopen (to, "wb");
  if (!fd) {
    DBG ("Couldn't open output file %s\n", to);
    goto end;
  }

  /* Write the header that was read by archive_open() */
  
  ARCHIVE_DAT_FILE_HEADER_TO_BE (dat_header);
  fwrite (&dat_header, sizeof(dat_header), 1, fd);
  ARCHIVE_DAT_FILE_HEADER_FROM_BE (dat_header);

  /* Then decrypt (automatically with paged_file_read) and write to file */
  
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

  if (ret && memcmp (dat_header.hash, file.digest, 0x14) != 0) {
    DBG ("HMAC hash does not match\n");
    ret = FALSE;
  }
  return ret;
}

int
archive_index_read (ArchiveIndex *archive_index, const char *path)
{
  PagedFile file = {0};
  DatFileHeader dat_header;

  archive_index->header.id = archive_index->footer.archive2_size = 0;
  archive_index->files = archive_index->dirs = NULL;
  archive_index->total_files = archive_index->total_file_sizes = archive_index->total_dirs = 0;

  if (!archive_open (path, &file, &dat_header)) {
    DBG ("Couldn't open file %s\n", path);
    goto end;
  }

  /* Read the archive header */
  
  if (paged_file_read (&file, &archive_index->header, sizeof(archive_index->header)) != sizeof(archive_index->header)) {
    DBG ("Couldn't read encrypted header from archive\n");
    goto end;
  }
  ARCHIVE_HEADER_FROM_BE (archive_index->header);

  /* Read the file list until the EOS file block */
  
  while(1) {
    ArchiveFile *archive_file = malloc (sizeof(ArchiveFile));
    if (paged_file_read (&file, archive_file, sizeof(ArchiveFile)) != sizeof(ArchiveFile)) {
      DBG ("Couldn't read file entry\n");
      goto end;
    }
	
    /* Found the last file */
	
    if (archive_file->eos.zero == 0) {
      ARCHIVE_FILE_EOS_FROM_BE (*archive_file);
      archive_index->total_files = archive_file->eos.total_files;
      archive_index->total_file_sizes = archive_file->eos.total_file_sizes;
      free (archive_file);
      break;
    }
    ARCHIVE_FILE_FROM_BE (*archive_file);
    archive_index->files = chained_list_append (archive_index->files, archive_file);
    DBG ("File : %s\n", archive_file->path);
  }
  
  /* Read the directory list until EOS directory block */
  
  while(1) {
    ArchiveDirectory *archive_dir = malloc (sizeof(ArchiveDirectory));
    if (paged_file_read (&file, archive_dir, sizeof(ArchiveDirectory)) != sizeof(ArchiveDirectory)) {
      DBG ("Couldn't read directory entry\n");
      goto end;
    }
	
    /* Found the last directory */
	
    if (archive_dir->eos.zero == 0) {
      ARCHIVE_DIRECTORY_EOS_FROM_BE (*archive_dir);
      archive_index->total_dirs = archive_dir->eos.total_dirs;
      free (archive_dir);
      break;
    }
    ARCHIVE_DIRECTORY_FROM_BE (*archive_dir);
    archive_index->dirs = chained_list_append (archive_index->dirs, archive_dir);
    DBG ("Directory : %s\n", archive_dir->path);
  }

  /* Read the footer for the non-protected archive index only */
  
  if (archive_index->header.archive_type == ARCHIVE_TYPE_NORMAL_CONTENT) {
    if (paged_file_read (&file, &archive_index->footer, sizeof(archive_index->footer)) != sizeof(archive_index->footer)) {
      DBG ("Couldn't read index archive footer\n");
      goto end;
    }
    ARCHIVE_INDEX_FOOTER_FROM_BE (archive_index->footer);
  }

  paged_file_close (&file);

  if (memcmp (dat_header.hash, file.digest, 0x14) != 0) {
    DBG ("HMAC hash does not match\n");
    return FALSE;
  }

  return TRUE;

 end:
  paged_file_close (&file);
  return FALSE;
}

int
archive_index_write (ArchiveIndex *archive_index, const char *path)
{
  FILE *fd = NULL;
  PagedFile file = {0};
  DatFileHeader dat_header;
  ArchiveFile file_eos;
  ArchiveDirectory dir_eos;
  ChainedList *list;
  u8 key[0x10];
  u8 iv[0x10];
  u8 hmac[0x40];

  if (!paged_file_open (&file, path, FALSE)) {
    DBG ("Couldn't open file %s\n", path);
    goto end;
  }

  dat_header.dat_type = DAT_TYPE_WITH_PROTECTED_ARCHIVE;
  if (archive_index->header.archive_type == ARCHIVE_TYPE_PROTECTED_CONTENT) {
    dat_header.encryption_type =  ENCRYPTION_TYPE_IDP;
    memset (dat_header.key_seed, 0, 0x14);
  } else {
	  
    /* If there is no copy-protected content, set type to 3 to avoid a warning */
	
    if (archive_index->footer.archive2_size == 0)
      dat_header.dat_type = DAT_TYPE_NO_PROTECTED_ARCHIVE;

    dat_header.encryption_type = ENCRYPTION_TYPE_KEYSEED;
    generate_random_key_seed (dat_header.key_seed);
  }
  memset (dat_header.padding, 0, 0x10);

  ARCHIVE_DAT_FILE_HEADER_TO_BE (dat_header);
  if (paged_file_write (&file, &dat_header, sizeof(dat_header)) != sizeof(dat_header)) {
    DBG ("Couldn't write file dat header\n");
    goto end;
  }
  ARCHIVE_DAT_FILE_HEADER_FROM_BE (dat_header);

  if (!archive_gen_keys (&dat_header, key, iv, hmac)) {
    DBG ("Error generating keys\n");
    goto end;
  }

  /* Flush the dat header before we enable HMAC hashing and encryption */
  
  paged_file_flush (&file);
  paged_file_hash (&file, hmac);
  paged_file_crypt (&file, key, iv, PAGED_FILE_CRYPT_AES_128_CBC, NULL, NULL);

  if (paged_file_write (&file, &archive_index->header, sizeof(archive_index->header)) != sizeof(archive_index->header)) {
    DBG ("Couldn't write index header for archive\n");
    goto end;
  }

  /* Write list of files */
  
  archive_index->total_files = 0;
  archive_index->total_file_sizes = 0;
  for (list = archive_index->files; list; list = list->next) {
    ArchiveFile *archive_file = list->data;

    archive_index->total_files++;
    archive_index->total_file_sizes += archive_file->fsstat.file_size;

    ARCHIVE_FILE_TO_BE (*archive_file);
    if (paged_file_write (&file, archive_file, sizeof(ArchiveFile)) != sizeof(ArchiveFile)) {
      DBG ("Couldn't write file entry\n");
      goto end;
    }
    ARCHIVE_FILE_FROM_BE (*archive_file);
  }
  
  /* Write file EOS */
  
  memset (&file_eos, 0, sizeof(ArchiveFile));
  file_eos.eos.zero = 0;
  file_eos.eos.total_files = archive_index->total_files;
  file_eos.eos.total_file_sizes = archive_index->total_file_sizes;

  ARCHIVE_FILE_EOS_TO_BE (file_eos);
  if (paged_file_write (&file, &file_eos, sizeof(ArchiveFile)) != sizeof(ArchiveFile)) {
    DBG ("Couldn't write file EOS\n");
    goto end;
  }
  ARCHIVE_FILE_EOS_FROM_BE (file_eos);

  /* Write list of directories */
  
  archive_index->total_dirs = 0;
  for (list = archive_index->dirs; list; list = list->next) {
    ArchiveDirectory *archive_dir = list->data;

    archive_index->total_dirs++;
    ARCHIVE_DIRECTORY_TO_BE (*archive_dir);
    if (paged_file_write (&file, archive_dir, sizeof(ArchiveDirectory)) != sizeof(ArchiveDirectory)) {
      DBG ("Couldn't write directory entry\n");
      goto end;
    }
    ARCHIVE_DIRECTORY_FROM_BE (*archive_dir);
  }

  /* Write EOS directory */
  
  memset (&dir_eos, 0, sizeof(ArchiveDirectory));
  dir_eos.eos.zero = 0;
  dir_eos.eos.total_dirs = archive_index->total_dirs;

  ARCHIVE_DIRECTORY_EOS_TO_BE (dir_eos);
  if (paged_file_write (&file, &dir_eos, sizeof(ArchiveDirectory)) != sizeof(ArchiveDirectory)) {
    DBG ("Couldn't write directory EOS\n");
    goto end;
  }
  ARCHIVE_DIRECTORY_EOS_FROM_BE (dir_eos);

  /* Write footer for non-protected index */
  
  if (archive_index->header.archive_type == ARCHIVE_TYPE_NORMAL_CONTENT) {
    archive_index->footer.padding = 0;

    ARCHIVE_INDEX_FOOTER_TO_BE (archive_index->footer);
    if (paged_file_write (&file, &archive_index->footer, sizeof(archive_index->footer)) != sizeof(archive_index->footer)) {
      DBG ("Couldn't write index footer for archive\n");
      goto end;
    }
    ARCHIVE_INDEX_FOOTER_FROM_BE (archive_index->footer);
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

static void
archive_index_free_cb (void *to_free, void *ignore)
{
  free (to_free);
}

void
archive_index_free (ArchiveIndex *archive_index)
{
  chained_list_foreach (archive_index->files, archive_index_free_cb, NULL);
  chained_list_foreach (archive_index->dirs, archive_index_free_cb, NULL);
  chained_list_free (archive_index->files);
  chained_list_free (archive_index->dirs);
}

int
archive_data_read (ArchiveData *archive_data, const char *path)
{
  PagedFile file = {0};
  DatFileHeader dat_header;
  int read;

  archive_data->header.id = archive_data->header.index = archive_data->header.archive_type = archive_data->header.file_type = 0;

  if (!archive_open (path, &file, &dat_header)) {
    DBG ("Couldn't open file %s\n", path);
    goto end;
  }

  if (paged_file_read (&file, &archive_data->header, sizeof(ArchiveHeader)) != sizeof(ArchiveHeader)) {
    DBG ("Couldn't read encrypted header\n");
    goto end;
  }
  ARCHIVE_HEADER_FROM_BE (archive_data->header);

  do {
    u8 buffer[1024];
    read = paged_file_read (&file, buffer, sizeof(buffer));
  } while (read > 0);

  paged_file_close (&file);

  if (memcmp (dat_header.hash, file.digest, 0x14) != 0) {
    DBG ("HMAC hash does not match\n");
    return FALSE;
  }

  return TRUE;

 end:
  paged_file_close (&file);
  return FALSE;
}

int
archive_find_file (ArchiveIndex *archive_index, const char *path,
    const char *filename, ArchiveFile **archive_file, u32 *index, u64 *position)
{
  ChainedList *current = archive_index->files;
  struct stat stat_buf;
  char data_path[1024];

  *index = 0;
  *position = 0x50; /* Skip header */
  snprintf (data_path, sizeof(data_path), "%s/%s_%02d.dat", path, archive_index->prefix, *index);
  if (stat (data_path, &stat_buf) != 0)
    return FALSE;

  while (current != NULL) {
    ArchiveFile *file = current->data;
    if (strcmp (file->path, filename) == 0) {
      *archive_file = file;
      return TRUE;
    }
    current = current->next;
    if (*position + file->fsstat.file_size >= (u64) stat_buf.st_size) {
      *position = 0x50 + (*position + file->fsstat.file_size) % stat_buf.st_size;
      (*index)++;
      snprintf (data_path, sizeof(data_path), "%s/%s_%02d.dat", path, archive_index->prefix, *index);
      if (stat (data_path, &stat_buf) != 0)
        return FALSE;
    } else {
      *position += file->fsstat.file_size;
    }
  }

  return FALSE;
}

int
archive_extract (ArchiveIndex *archive_index, const char *path, u32 index,
    u64 offset, u64 size, const char *output)
{
  char filename[1024];
  DatFileHeader dat_header;
  ArchiveHeader archive_header;
  PagedFile in = {0};
  PagedFile out = {0};

  if (!paged_file_open (&out, output, FALSE))
    die ("Couldn't open output file : %s\n", output);

  while (size > 0) {
    u64 read; // fix a potential overflow

    snprintf (filename, sizeof(filename), "%s/%s_%02d.dat", path, archive_index->prefix, index);
    if (!archive_open (filename, &in, &dat_header))
      die ("Couldn't open archive %d\n", index);

    if (paged_file_read (&in, &archive_header, sizeof(archive_header)) != sizeof(archive_header))
      die ("Couldn't read archive header\n");
    ARCHIVE_HEADER_FROM_BE (archive_header);

    if (archive_header.id != archive_index->header.id)
      die ("Wrong archive ID\n");
    if (archive_header.index != index)
      die ("Wrong archive index\n");
    paged_file_seek (&in, offset);
    index++;
    offset = 0x50;

    read = paged_file_splice (&out, &in, size);
    size -= read;
    paged_file_close (&in);
  }

  paged_file_close (&out);

  return TRUE;
}

int
archive_extract_file (const char *path, const char *filename, const char *output)
{
  ArchiveIndex archive;
  ArchiveFile *file = NULL;
  char buffer[1024];
  u32 index;
  u64 offset;
  int ret = FALSE;

  /* Try to extract from archive.dat */
  
  archive.prefix = "archive";
  snprintf (buffer, sizeof(buffer), "%s/%s.dat", path, archive.prefix);
  if (!archive_index_read (&archive, buffer))
    die ("Unable to read index archive\n");

  if (archive_find_file (&archive, path, filename, &file, &index, &offset)) {
    ret = archive_extract (&archive, path, index, offset, file->fsstat.file_size, output);
  } else if (device_id_set) {
    ArchiveIndex archive2;

    archive2.prefix = "archive2";
	
    /* Extract from archive2.dat */
	
    snprintf (buffer, sizeof(buffer), "%s/%s.dat", path, archive2.prefix);
    if (!archive_index_read (&archive2, buffer))
      die ("Unable to read index archive\n");

    if (archive_find_file (&archive2, path, filename, &file, &index, &offset))
      ret = archive_extract (&archive2, path, index, offset, file->fsstat.file_size, output);
    archive_index_free (&archive2);
  }

  archive_index_free (&archive);

  return ret;
}

static void
archive_append_file_to_list_cb (ArchiveFile *file, ChainedList **list)
{
  *list = chained_list_append (*list, file);
}

int
archive_extract_path (const char *path, const char *match, const char *output)
{
  ChainedList *all_files = NULL;
  ChainedList *current;
  ArchiveIndex archive = {0};
  ArchiveIndex archive2 = {0};
  char buffer[2048];
  int match_len = strlen (match);

  /* Try to extract from archive.dat */
  
  archive.prefix = "archive";
  snprintf (buffer, sizeof(buffer), "%s/%s.dat", path, archive.prefix);
  if (!archive_index_read (&archive, buffer))
    die ("Unable to read index archive\n");

  chained_list_foreach (archive.files,
      (ChainedListForeachCallback) archive_append_file_to_list_cb, &all_files);

  /* Try to extract from archive2.dat */
  
  if (device_id_set) {
    archive2.prefix = "archive2";
    snprintf (buffer, sizeof(buffer), "%s/%s.dat", path, archive2.prefix);
    if (!archive_index_read (&archive2, buffer))
      die ("Unable to read index archive\n");

    chained_list_foreach (archive2.files,
        (ChainedListForeachCallback) archive_append_file_to_list_cb, &all_files);
  }

  current = all_files;
  while (current != NULL) {
    ArchiveFile *file = current->data;
    if (strncmp (file->path, match, match_len) == 0) {
      int i;

      snprintf (buffer, sizeof(buffer), "%s/%s", output, file->path);
      i = strlen (buffer);
      while (i > 0 && buffer[i] != '/') i--;
      if (i > 0) {
        buffer[i] = 0;
        mkdir_recursive (buffer);
        buffer[i] = '/';
      }
      if (!archive_extract_file (path, file->path, buffer))
        return FALSE;
    }
    current = current->next;
  }
  archive_index_free (&archive);
  archive_index_free (&archive2);
  chained_list_free (all_files);

  return TRUE;
}

int
archive_rename_file (const char *path, const char *filename, const char *destination)
{
  ArchiveIndex archive;
  ArchiveFile *file = NULL;
  char buffer[1024];
  u32 index;
  u64 offset;

  /* Try to extract from archive.dat */
  
  archive.prefix = "archive";
  snprintf (buffer, sizeof(buffer), "%s/%s.dat", path, archive.prefix);
  if (!archive_index_read (&archive, buffer))
    die ("Unable to read index archive\n");

  if (archive_find_file (&archive, path, filename, &file, &index, &offset)) {
    strcpy (file->path, destination);
    if (!archive_index_write (&archive, buffer))
      die ("Unable to write index archive\n");
  }
  archive_index_free (&archive);

  if (device_id_set) {
    ArchiveIndex archive2;

    archive2.prefix = "archive2";
	
    /* Extract from archive2.dat */
	
    snprintf (buffer, sizeof(buffer), "%s/%s.dat", path, archive2.prefix);
    if (!archive_index_read (&archive2, buffer))
      die ("Unable to read index archive\n");

    if (archive_find_file (&archive2, path, filename, &file, &index, &offset)) {
      strcpy (file->path, destination);
      if (!archive_index_write (&archive2, buffer))
        die ("Unable to write index archive\n");
    }
    archive_index_free (&archive2);
  }

  return TRUE;
}

int
archive_rename_path (const char *path, const char *match, const char *destination)
{
  ChainedList *all_files = NULL;
  ChainedList *current;
  ArchiveIndex archive = {0};
  ArchiveIndex archive2 = {0};
  char buffer[2048];
  int match_len = strlen (match);

  /* Try to extract from archive.dat */
  
  archive.prefix = "archive";
  snprintf (buffer, sizeof(buffer), "%s/%s.dat", path, archive.prefix);
  if (!archive_index_read (&archive, buffer))
    die ("Unable to read index archive\n");

  chained_list_foreach (archive.files,
      (ChainedListForeachCallback) archive_append_file_to_list_cb, &all_files);

  /* Try to extract from archive2.dat */
  
  if (device_id_set) {
    archive2.prefix = "archive2";
    snprintf (buffer, sizeof(buffer), "%s/%s.dat", path, archive2.prefix);
    if (!archive_index_read (&archive2, buffer))
      die ("Unable to read index archive\n");

    chained_list_foreach (archive2.files,
        (ChainedListForeachCallback) archive_append_file_to_list_cb, &all_files);
  }

  current = all_files;
  while (current != NULL) {
    ArchiveFile *file = current->data;
    if (strncmp (file->path, match, match_len) == 0) {
      if (!archive_rename_file (path, file->path, destination))
        return FALSE;
    }
    current = current->next;
  }

  archive_index_free (&archive);
  archive_index_free (&archive2);
  chained_list_free (all_files);

  return TRUE;
}

int
archive_dump (const char *path, const char *prefix, const char *output)
{
  ChainedList *list = NULL;
  char buffer[0x10000];
  ArchiveIndex archive_index;
  DatFileHeader dat_header;
  ArchiveHeader archive_header;
  PagedFile pf = {0};
  u32 index = 0;
  int open = FALSE;

  snprintf (buffer, sizeof(buffer), "%s/%s.dat", path, prefix);
  archive_index.prefix = prefix;
  if (!archive_index_read (&archive_index, buffer))
    die ("Unable to read index archive\n");

  for (list = archive_index.dirs; list; list = list->next) {
    ArchiveDirectory *dir = list->data;

    snprintf (buffer, sizeof(buffer), "%s/%s", output, dir->path);
    if (mkdir_recursive (buffer) != 0)
      die ("Error making directories\n");
  }

  for (list = archive_index.files; list; list = list->next) {
    ArchiveFile *file = list->data;
    FILE *fd;
    u64 len = file->fsstat.file_size;

    snprintf (buffer, sizeof(buffer), "%s/%s", output, file->path);
    fd = fopen (buffer, "wb");
    if (!fd)
      die ("Error opening output file %s\n", buffer);
    while (len > 0) {
      u64 read;
      u64 size = len;

      if (!open) {
        snprintf (buffer, sizeof(buffer), "%s/%s_%02d.dat", path, prefix, index);
        if (!archive_open (buffer, &pf, &dat_header)) {
          die ("Couldn't open archive %d\n", index);
        }

        if (paged_file_read (&pf, &archive_header, sizeof(archive_header)) != sizeof(archive_header))
          die ("Couldn't read archive header\n");
        ARCHIVE_HEADER_FROM_BE (archive_header);

        if (archive_header.id != archive_index.header.id)
          die ("Wrong archive ID\n");
        if (archive_header.index != index)
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

  if (open)
    paged_file_close (&pf);
  archive_index_free (&archive_index);

  return TRUE;
}

int
archive_dump_all (const char *path, const char *output)
{
  int ret;

  ret = archive_dump (path, "archive", output);
  if (ret && device_id_set)
    archive_dump (path, "archive2", output);

  return ret;
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
    const char *base, const char *subdir, DIR *fd, int protected)
{
  struct dirent *dirent = NULL;
  struct stat stat_buf;
  char path[1024];
  int dev_flash2;

  while (1) {
    dirent = readdir (fd);
    if (!dirent)
      break;
    if (strcmp (dirent->d_name, ".") == 0 ||
        strcmp (dirent->d_name, "..") == 0)
      continue;

    DBG ("Found %s : %s/%s\n", dirent->d_type == DT_DIR ? "directory" : "file" ,
        subdir, dirent->d_name);
    if (dirent->d_type == DT_DIR) {
      ArchiveDirectory *archive_dir = malloc (sizeof(ArchiveDirectory));
      DIR *dir_fd = NULL;

      snprintf (path, sizeof(path), "%s/%s/%s", base, subdir, dirent->d_name);
      snprintf (archive_dir->path, sizeof(archive_dir->path), "%s/%s",
          subdir, dirent->d_name);
      stat (path, &stat_buf);

      dev_flash2 = strncmp (archive_dir->path, "/dev_flash2", 11) == 0;
      if (strcmp (archive_dir->path, "/dev_hdd0/game") == 0)
        archive_dir->fsstat.mode = 0x41FF;
      else if (strncmp (archive_dir->path, "/dev_hdd0/game/", 15) ==0)
        archive_dir->fsstat.mode = 0x41FF;
      else if (dev_flash2)
        archive_dir->fsstat.mode = 0x41C9;
      else
        archive_dir->fsstat.mode = 0x41FF;

      archive_dir->fsstat.uid = 0;
      archive_dir->fsstat.gid = dev_flash2 ? 0 : -1;
      archive_dir->fsstat.atime = stat_buf.st_atime;
      archive_dir->fsstat.mtime = stat_buf.st_mtime;
      archive_dir->fsstat.ctime = stat_buf.st_ctime;
      archive_dir->fsstat.file_size = 0x200;
      archive_dir->fsstat.block_size = 0x200;
      archive_dir->flags = dev_flash2 ? 2 : (protected ? 0 : 1);
      *dirs = chained_list_append (*dirs, archive_dir);

      dir_fd = opendir(path);
      if (!dir_fd)
        die ("Unable to open subdirectory\n");
      populate_dirlist (dirs, files, base, archive_dir->path, dir_fd, protected);
      closedir (dir_fd);
    } else {
      ArchiveFile *archive_file = malloc (sizeof(ArchiveFile));

      snprintf (path, sizeof(path), "%s/%s/%s", base, subdir, dirent->d_name);
      snprintf (archive_file->path, sizeof(archive_file->path), "%s/%s",
          subdir, dirent->d_name);
      stat (path, &stat_buf);

      dev_flash2 = strncmp (archive_file->path, "/dev_flash2", 11) == 0;
      if (strncmp (archive_file->path, "/dev_hdd0/game/", 15) ==0)
        archive_file->fsstat.mode = 0x81B6;
      else if (dev_flash2)
        archive_file->fsstat.mode = 0x8180;
      else
        archive_file->fsstat.mode = 0x81B6;

      archive_file->fsstat.uid = 0;
      archive_file->fsstat.gid = dev_flash2 ? 0 : -1;
      archive_file->fsstat.atime = stat_buf.st_atime;
      archive_file->fsstat.mtime = stat_buf.st_mtime;
      archive_file->fsstat.ctime = stat_buf.st_ctime;
      archive_file->fsstat.file_size = stat_buf.st_size;
      archive_file->fsstat.block_size = 0x200;
      archive_file->flags = dev_flash2 ? 1 : 0;
      *files = chained_list_append (*files, archive_file);
    }
  }
}

int
archive_add (const char *path, const char *game, int protected)
{
  ChainedList *list = NULL;
  char buffer[0x10000];
  ArchiveIndex archive = {0};
  ArchiveIndex archive_index = {0};
  DatFileHeader dat_header;
  ArchiveHeader archive_header;
  ChainedList *dirs = NULL;
  ChainedList *files = NULL;
  PagedFile in = {0};
  PagedFile out = {0};
  u32 index = 0;
  FILE *fd = NULL;
  DIR *dir_fd = NULL;
  u32 total_file_size = 0;
  int new_file = FALSE;
  u8 key[0x10];
  u8 iv[0x10];
  u8 hmac[0x40];

  if (protected)
    archive_index.prefix = "archive2";
  else
    archive_index.prefix = "archive";

  dir_fd = opendir(game);
  if (!dir_fd)
    die ("Unable to open game directory\n");

  populate_dirlist (&dirs, &files, game, "", dir_fd, protected);
  closedir (dir_fd);

  if (protected) {
    archive.prefix = "archive";
    snprintf (buffer, sizeof(buffer), "%s/archive.dat", path);
    if (!archive_index_read (&archive, buffer))
      die ("Unable to read main index archive\n");
  }

  snprintf (buffer, sizeof(buffer), "%s/%s.dat", path, archive_index.prefix);
  if (!file_exists (buffer)) {
    if (!protected)
      die ("Invalid backup directory, call CreateBackup if you need to create one\n");

    archive_index.header.id = archive.header.id;
    archive_index.header.index = 0;
    archive_index.header.archive_type = ARCHIVE_TYPE_PROTECTED_CONTENT;
    archive_index.header.file_type = FILE_TYPE_INDEX;
  } else {
    if (!archive_index_read (&archive_index, buffer))
      die ("Unable to read index archive\n");
  }

  for (list = dirs; list; list = list->next) {
    ArchiveDirectory *dir = list->data;

    if (strcmp (dir->path, "/dev_hdd0") == 0 ||
        strcmp (dir->path, "/dev_flash2") == 0 ||
        chained_list_contains_string (archive_index.dirs, dir->path)) {
      free (dir);
      continue;
    }
    archive_index.dirs = chained_list_append (archive_index.dirs, dir);
  }
  chained_list_free (dirs);

  while (1) {
    snprintf (buffer, sizeof(buffer), "%s/%s_%02d.dat", path, archive_index.prefix, index);
    if (!file_exists (buffer)) {
      if (index == 0)
        break;
      if (!new_file)
        index--;
      break;
    }
    index++;
  }

  snprintf (buffer, sizeof(buffer), "%s/%s_%02d.dat", path, archive_index.prefix, index);
  if (file_exists (buffer)) {
    if (!archive_open (buffer, &in, &dat_header))
      die ("Couldn't open archive %d\n", index);

    if (paged_file_read (&in, &archive_header, sizeof(archive_header)) != sizeof(archive_header))
      die ("Couldn't read header\n");
    ARCHIVE_HEADER_FROM_BE (archive_header);

    if (archive_header.id != archive_index.header.id)
      die ("Wrong archive ID\n");
    if (archive_header.index != index)
      die ("Wrong archive index\n");
    snprintf (buffer, sizeof(buffer), "%s/%s_%02d.tmp", path, archive_index.prefix, index);

    if (!paged_file_open (&out, buffer, FALSE))
      die ("Couldn't open output archive %d\n", index);

    ARCHIVE_DAT_FILE_HEADER_TO_BE (dat_header);
    if (paged_file_write (&out, &dat_header, sizeof(dat_header)) != sizeof(dat_header))
      die ("Couldn't write file dat header\n");
    ARCHIVE_DAT_FILE_HEADER_FROM_BE (dat_header);

    total_file_size += sizeof(dat_header);

    if (!archive_gen_keys (&dat_header, key, iv, hmac))
      die ("Error generating keys\n");

    paged_file_flush (&out);
    paged_file_hash (&out, hmac);
    paged_file_crypt (&out, key, iv, PAGED_FILE_CRYPT_AES_128_CBC, NULL, NULL);

    if (paged_file_write (&out, &archive_header, sizeof(archive_header)) != sizeof(archive_header))
      die ("Couldn't write encrypted header\n");
    total_file_size += sizeof(archive_header);
    total_file_size += paged_file_splice (&out, &in, -1);
    if (total_file_size > 0xFFFFFE00)
      die ("Output file is too big\n");
    paged_file_close (&in);
    new_file = FALSE;
  } else {
    if (protected) {
      dat_header.encryption_type =  ENCRYPTION_TYPE_IDP;
      memset (dat_header.key_seed, 0, 0x14);
    } else {
      dat_header.encryption_type = ENCRYPTION_TYPE_KEYSEED;
      generate_random_key_seed (dat_header.key_seed);
    }
    dat_header.dat_type = DAT_TYPE_WITH_PROTECTED_ARCHIVE;
    memset (dat_header.padding, 0, 0x10);

    archive_header = archive_index.header;
    archive_header.index = index;
    archive_header.archive_type = ARCHIVE_TYPE_NORMAL_CONTENT;
    archive_header.file_type = FILE_TYPE_DATA;

    snprintf (buffer, sizeof(buffer), "%s/%s_%02d.dat", path, archive_index.prefix, index);

    if (!paged_file_open (&out, buffer, FALSE))
      die ("Couldn't open output archive %d\n", index);

    ARCHIVE_DAT_FILE_HEADER_TO_BE (dat_header);
    if (paged_file_write (&out, &dat_header, sizeof(dat_header)) != sizeof(dat_header))
      die ("Couldn't write file dat header\n");
    ARCHIVE_DAT_FILE_HEADER_FROM_BE (dat_header);

    total_file_size += sizeof(dat_header);

    if (!archive_gen_keys (&dat_header, key, iv, hmac))
      die ("Error generating keys\n");

    paged_file_flush (&out);
    paged_file_hash (&out, hmac);
    paged_file_crypt (&out, key, iv, PAGED_FILE_CRYPT_AES_128_CBC, NULL, NULL);

    ARCHIVE_HEADER_TO_BE (archive_header);
    if (paged_file_write (&out, &archive_header, sizeof(archive_header)) != sizeof(archive_header))
      die ("Couldn't write encrypted header\n");
    ARCHIVE_HEADER_TO_BE (archive_header);

    total_file_size += sizeof(archive_header);
    new_file = TRUE;
  }

  for (list = files; list; list = list->next) {
    ArchiveFile *file = list->data;

    if (chained_list_contains_string (archive_index.files, file->path)) {
      fprintf (stderr, "Ignoring already existing file %s\n", file->path);
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
	
      /* TODO: Must be able to exceed a file size of 0xFFFFFE00 by splitting */
	  
      if (total_file_size + read > 0xFFFFFE00)
        die ("Output file is too big\n");
      paged_file_write (&out, buffer, read);
      total_file_size += read;
    }

    fclose (fd);
    archive_index.files = chained_list_append (archive_index.files, file);
  }
  paged_file_flush (&out);
  fd = out.fd;
  out.fd = NULL;
  paged_file_close (&out);

  fseek (fd, 8, SEEK_SET);
  fwrite (out.digest, 0x14, 1, fd);
  fclose (fd);

  if (!new_file) {
    snprintf (buffer, 0x500, "%s/%s_%02d.bak", path, archive_index.prefix, index);
    snprintf (buffer + 0x500, 0x500, "%s/%s_%02d.dat", path, archive_index.prefix, index);
    if (rename (buffer + 0x500, buffer) != 0)
      die ("File rename failed\n");
    snprintf (buffer, 0x500, "%s/%s_%02d.tmp", path, archive_index.prefix, index);
    if (rename (buffer, buffer + 0x500) != 0)
      die ("File rename failed\n");
  }
  snprintf (buffer, 0x500, "%s/%s.dat", path, archive_index.prefix);
  snprintf (buffer + 0x500, 0x500, "%s/%s.bak", path, archive_index.prefix);
  if (rename (buffer, buffer + 0x500) != 0)
    die ("File rename failed\n");
  if (!archive_index_write (&archive_index, buffer))
    die ("Unable to write index archive\n");

  if (protected) {
    archive.footer.archive2_size = archive_index.total_file_sizes;
    snprintf (buffer, 0x500, "%s/%s.dat", path, archive.prefix);
    archive_index_write (&archive, buffer);
  }

  archive_index_free (&archive);
  archive_index_free (&archive_index);

  return TRUE;
}

int
archive_create_backup (const char *path, const char *content, const char *protected_content)
{
  ArchiveIndex archive = {0};
  ArchiveIndex archive2 = {0};
  char filename[1024];
  u64 archive_id;

  mkdir_recursive (path);
  get_rand ((u8 *)&archive_id, 8);

  archive.prefix = "archive";
  archive.header.id = archive_id;
  archive.header.index = 0;
  archive.header.archive_type = ARCHIVE_TYPE_NORMAL_CONTENT;
  archive.header.file_type = FILE_TYPE_INDEX;
  memcpy (archive.footer.psid, open_psid, 0x10);
  archive.footer.archive2_size = 0;

  snprintf (filename, sizeof(filename), "%s/%s.dat", path, archive.prefix);
  if (!archive_index_write (&archive, filename))
    die ("Unable to write index archive\n");

  if (content &&
      content[0] != 0 &&
      (content[0] != '-' || content[1] != 0) ) {

    if (archive_add (path, content, FALSE) == FALSE)
      return FALSE;
    snprintf (filename, sizeof(filename), "%s/%s.bak", path, archive.prefix);
    remove (filename);
  }


  if (protected_content &&
      protected_content[0] != 0 &&
      (protected_content[0] != '-' || protected_content[1] != 0)) {
    archive2.prefix = "archive2";
    archive2.header.id = archive_id;
    archive2.header.index = 0;
    archive2.header.archive_type = ARCHIVE_TYPE_PROTECTED_CONTENT;
    archive2.header.file_type = FILE_TYPE_INDEX;

    snprintf (filename, sizeof(filename), "%s/%s.dat", path, archive2.prefix);
    if (!archive_index_write (&archive2, filename))
      die ("Unable to write index archive\n");

    if (archive_add (path, protected_content, TRUE) == FALSE)
      return FALSE;

    if (!archive_index_read (&archive2, filename))
      die ("Unable to read index archive\n");

    snprintf (filename, sizeof(filename), "%s/%s.bak", path, archive2.prefix);
    remove (filename);
  }

  archive_index_free (&archive);
  archive_index_free (&archive2);

  return TRUE;
}

int
archive_delete_protected (const char *path)
{
  ArchiveIndex archive;
  char buffer[1024];

  archive.prefix = "archive";
  snprintf (buffer, sizeof(buffer), "%s/%s.dat", path, archive.prefix);
  if (!archive_index_read (&archive, buffer))
    die ("Unable to read index archive\n");

  archive.footer.archive2_size = 0;
  if (!archive_index_write (&archive, buffer))
    die ("Unable to write index archive\n");

  archive_index_free (&archive);

  return TRUE;
}

void
archive_set_device_id (const u8 idps[0x10])
{
  memcpy (device_id, idps, 0x10);
  device_id_set = TRUE;
}

void
archive_set_open_psid (const u8 psid[0x10])
{
  memcpy (open_psid, psid, 0x10);
  open_psid_set = TRUE;
}
