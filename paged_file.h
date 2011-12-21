// 2011 Ninjas
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt

#ifndef __PAGED_FILE_H__
#define __PAGED_FILE_H__

#include "tools.h"
#include "types.h"
#include "common.h"

#include <stdio.h>

#define PAGED_FILE_PAGE_SIZE 0x10000

typedef struct {
  FILE *fd;
  int reader;
  u8 *ptr;
  u32 size;
  u32 pos;
  HMACContext hmac_ctx;
  u8 key[0x10];
  u8 iv[0x10];
  u8 digest[0x14];
  int crypt;
  int hash;
} PagedFile;

int paged_file_open (PagedFile *f, const char *path, int reader);
int paged_file_crypt (PagedFile *f, u8 *key, u8 *iv);
int paged_file_hash (PagedFile *f, u8 *key);
int paged_file_read (PagedFile *f, void *buffer, u32 len);
int paged_file_getline (PagedFile *f, char **line, int *line_len);
int paged_file_write (PagedFile *f, void *buffer, u32 len);
int paged_file_splice (PagedFile *f, PagedFile *from, int len);
int paged_file_flush (PagedFile *f);
void paged_file_free (PagedFile *f);
void paged_file_close (PagedFile *f);

#endif /* __PAGED_FILE_H__ */
