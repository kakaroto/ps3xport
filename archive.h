/*
 * Copyright (C) The Freedom League
 *
 * This software is distributed under the terms of the GNU General Public
 * License ("GPL") version 3, as published by the Free Software Foundation.
 *
 */

#ifndef __ARCHIVE_H__
#define __ARCHIVE_H__

#include "tools.h"
#include "types.h"
#include "common.h"

extern Key *keys;
extern int num_keys;
extern const char *keys_conf_path;

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
} __attribute__((packed)) FileStat;

#define ARCHIVE_FILE_STAT_FROM_BE(x)                \
  (x).mode = FROM_BE (32, (x).mode);                \
     (x).uid = FROM_BE (32, (x).uid);               \
     (x).gid = FROM_BE (32, (x).gid);               \
     (x).atime = FROM_BE (64, (x).atime);           \
     (x).mtime = FROM_BE (64, (x).mtime);           \
     (x).ctime = FROM_BE (64, (x).ctime);           \
     (x).file_size = FROM_BE (64, (x).file_size);   \
     (x).block_size = FROM_BE (64, (x).block_size);

#define ARCHIVE_FILE_STAT_TO_BE(x) ARCHIVE_FILE_STAT_FROM_BE (x)

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
} __attribute__((packed)) ArchiveFile;

#define ARCHIVE_FILE_FROM_BE(x)                 \
  ARCHIVE_FILE_STAT_FROM_BE ((x).stat);         \
  (x).flags = FROM_BE (32, (x).flags);
#define ARCHIVE_FILE_TO_BE(x) ARCHIVE_FILE_FROM_BE (x)

#define ARCHIVE_FILE_EOS_FROM_BE(x)                                     \
  (x).eos.total_files = FROM_BE (64, (x).eos.total_files);              \
     (x).eos.total_file_sizes = FROM_BE (64, (x).eos.total_file_sizes);
#define ARCHIVE_FILE_EOS_TO_BE(x) ARCHIVE_FILE_EOS_FROM_BE (x)

typedef struct {
  union {
    char path[0x420];
    struct {
      u64 zero;
      u64 total_dirs;
    } eos;
  };
  FileStat stat;
  u32 flags; /* must be 1 for normal or 3 for dev_flash2 */
} __attribute__((packed)) ArchiveDirectory;

#define ARCHIVE_DIRECTORY_FROM_BE(x)                 \
  ARCHIVE_FILE_STAT_FROM_BE ((x).stat);              \
  (x).flags = FROM_BE (32, (x).flags);
#define ARCHIVE_DIRECTORY_TO_BE(x) ARCHIVE_DIRECTORY_FROM_BE (x)

#define ARCHIVE_DIRECTORY_EOS_FROM_BE(x)                                \
  (x).eos.total_dirs = FROM_BE (64, (x).eos.total_dirs);
#define ARCHIVE_DIRECTORY_EOS_TO_BE(x) ARCHIVE_DIRECTORY_EOS_FROM_BE (x)

typedef struct {
  u32 size;
  u32 type;
  u8 hash[0x14];
  u8 key_seed[0x14];
  u8 padding[0x10];
} __attribute__((packed)) DatFileHeader;

#define ARCHIVE_DAT_FILE_HEADER_FROM_BE(x)                 \
  (x).size = FROM_LE (32, (x).size);                       \
  (x).type = FROM_BE (32, (x).type);
#define ARCHIVE_DAT_FILE_HEADER_TO_BE(x) ARCHIVE_DAT_FILE_HEADER_FROM_BE (x)


typedef struct {
  u64 id;
  u32 index;
  u8 archive_type; // 4 for copy protected, 5 for normal.
  u8 id_type; // 1 means the archive_id is the current ticks ? 0 means system time ?
  u16 padding;
} __attribute__((packed)) ArchiveHeader;

#define ARCHIVE_HEADER_FROM_BE(x)               \
  (x).index = FROM_BE (32, (x).index);
#define ARCHIVE_HEADER_TO_BE(x) ARCHIVE_HEADER_FROM_BE (x)

typedef struct {
  u8 psid[0x10];
  u64 archive2_size;
  u64 padding;
} __attribute__((packed)) ArchiveIndexFooter;

#define ARCHIVE_INDEX_FOOTER_FROM_BE(x)                 \
  (x).archive2_size = FROM_BE (64, (x).archive2_size);
#define ARCHIVE_INDEX_FOOTER_TO_BE(x) ARCHIVE_INDEX_FOOTER_FROM_BE (x)

typedef struct {
  const char *prefix;
  ArchiveHeader header;
  ArchiveIndexFooter footer;
  ChainedList *files;
  u64 total_files;
  u64 total_file_sizes;
  ChainedList *dirs;
  u64 total_dirs;
} ArchiveIndex;

typedef struct {
  ArchiveHeader header;
} ArchiveData;


ChainedList *chained_list_append (ChainedList *list, void *data);
void chained_list_foreach (ChainedList *list, ChainedListForeachCallback cb, void *user_data);
void chained_list_free (ChainedList *list);

int archive_open (const char *path, PagedFile *file, DatFileHeader *dat_header);
int archive_decrypt (const char *path, const char *to);
int archive_index_read (ArchiveIndex *archive_index, const char *path);
int archive_index_write (ArchiveIndex *archive_index, const char *path);
void archive_index_free (ArchiveIndex *archive_index);
int archive_data_read (ArchiveData *archive_data, const char *path);
int archive_find_file (ArchiveIndex *archive, const char *path,
    const char *filename, ArchiveFile **archive_file, u32 *index, u64 *position);
int archive_dump (const char *path, const char *prefix, const char *output);
int archive_extract (ArchiveIndex *archive_index, const char *path, u32 index,
    u64 offset, u64 size, const char *output);
int archive_extract_file (const char *path, const char *filename, const char *output);
int archive_extract_path (const char *path, const char *match, const char *output);
int archive_rename_file (const char *path, const char *filename, const char *destination);
int archive_rename_path (const char *path, const char *match, const char *destination);
int archive_dump_all (const char *path, const char *output);
int archive_add (const char *path, const char *game, int protected);
int archive_create_backup (const char *path, const char *content, const char *protected_content);
int archive_delete_protected (const char *path);
void archive_set_device_id (const u8 idps[0x10]);
void archive_set_open_psid (const u8 psid[0x10]);

#endif /* __ARCHIVE_H__ */
