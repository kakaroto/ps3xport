// 2011 Ninjas
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt

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
  u32 flags; /* must be 1 for normal or 3 for dev_flash2 */
} ArchiveDirectory;

typedef struct {
  u32 size;
  u32 type;
  u8 hash[0x14];
  u8 key_seed[0x14];
  u8 padding[0x10];
} DatFileHeader;

typedef struct {
  u64 id;
  u32 index;
  u8 archive_type; // 4 for copy protected, 5 for normal.
  u8 id_type; // 1 means the archive_id is the current ticks ? 0 means system time ?
  u16 padding;
} ArchiveHeader;

typedef struct {
  u8 psid[0x10];
  u64 archive2_size;
  u64 padding;
} ArchiveIndexFooter;

typedef struct {
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
int index_archive_read (ArchiveIndex *archive_index, const char *path);
int index_archive_write (ArchiveIndex *archive_index, const char *path);
int data_archive_read (ArchiveData *archive_data, const char *path);
int archive_find_file (ArchiveIndex *archive, const char *prefix,
    const char *path, ArchiveFile **archive_file, u32 *index, u64 *position);
int archive_dump (const char *path, const char *prefix, const char *output);
int archive_dump_all (const char *path, const char *output);
int archive_add (const char *path, const char *game);
int archive_set_device_id (const u8 idps[0x10]);


#endif /* __ARCHIVE_H__ */
