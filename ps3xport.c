/*
 * Copyright (C) The Freedom League
 *
 * This software is distributed under the terms of the GNU General Public
 * License ("GPL") version 3, as published by the Free Software Foundation.
 *
 */

#include "tools.h"
#include "types.h"
#include "common.h"
#include "keys.h"

#include "paged_file.h"
#include "archive.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>

#define PS3XPORT_VERSION "0.2"

#define USAGE_STRING "PS3xport v" PS3XPORT_VERSION "\n"                 \
  "  Usage: %s command [argument ...] [command ...]\n"                  \
  "    Commands : \n"                                                   \
  "\t  SetKeysFile filename:\n"                                         \
  "\t\t  Set the path to the keys.conf file  (default: keys.conf)\n"    \
  "\t  SetDeviceID (HEX|filename):\n"                                   \
  "\t\t  Set the DeviceID needed for decrypting archive2.dat\n"         \
  "\t  SetPSID (HEX|filename):\n"                                       \
  "\t\t  Set the OpenPSID needed for creating new backups\n"            \
  "\t  ExtractPSID backup_dir output:\n"                                \
  "\t\t  Extract the OpenPSID from a backup directory\n"                \
  "\t  ReadIndex archive.dat:\n"                                        \
  "\t\t  Parse the specified index file and print info\n"               \
  "\t  ReadData archive_XX.dat:\n"                                      \
  "\t\t  Parse the specified data file and print info\n"                \
  "\t  Decrypt archive[_XX].dat decrypted.dat:\n"                       \
  "\t\t  Decrypt the given .dat file\n"                                 \
  "\t  Dump backup_dir destination_dir:\n"                              \
  "\t\t  Extract the whole backup to the destination directory\n"       \
  "\t  ExtractFile backup_dir filename destination:\n"                  \
  "\t\t  Extract from a backup a specific file\n"                       \
  "\t  ExtractPath backup_dir path destination_dir:\n"                  \
  "\t\t  Extract from a backup all files matching the specified path\n" \
  "\t  DeleteFile backup_dir filename:\n"                               \
  "\t\t  Delete from a backup a specific file\n"                        \
  "\t  DeletePath backup_dir path:\n"                                   \
  "\t\t  Delete from a backup all files matching the specified path\n"  \
  "\t  DeleteProtected backup_dir\n"                                    \
  "\t\t  Deletes the copy-protected files from the backup\n"            \
  "\t  Add backup_dir directory:\n"                                     \
  "\t\t  Add the given directory and subdirs to the backup\n"           \
  "\t  AddProtected backup_dir directory:\n"                            \
  "\t\t  Add the given directory and subdirs to the copy-protected backup\n" \
  "\t  CreateBackup backup_dir content protected_content\n"             \
  "\t\t  Create a new backup with a content dir and a copy-protected content\n" \
  "\t\t    Set the content path to '-' to ignore it\n\n"

static void
archive_print_dir (ArchiveDirectory *dir, char *prefix)
{
  printf ("%s d%c%c%c%c%c%c%c%c%c %s\n", prefix,
      dir->fsstat.mode & 0400 ? 'r' : '-',
      dir->fsstat.mode & 0200 ? 'w' : '-',
      dir->fsstat.mode & 0100 ? 'x' : '-',
      dir->fsstat.mode & 040 ? 'r' : '-',
      dir->fsstat.mode & 020 ? 'w' : '-',
      dir->fsstat.mode & 010 ? 'x' : '-',
      dir->fsstat.mode & 04 ? 'r' : '-',
      dir->fsstat.mode & 02 ? 'w' : '-',
      dir->fsstat.mode & 01 ? 'x' : '-',
      dir->path);
}
static void
archive_print_file (ArchiveFile *file, char *prefix)
{
  printf ("%s -%c%c%c%c%c%c%c%c%c %10" U64_FORMAT " %s\n", prefix,
      file->fsstat.mode & 0400 ? 'r' : '-',
      file->fsstat.mode & 0200 ? 'w' : '-',
      file->fsstat.mode & 0100 ? 'x' : '-',
      file->fsstat.mode & 040 ? 'r' : '-',
      file->fsstat.mode & 020 ? 'w' : '-',
      file->fsstat.mode & 010 ? 'x' : '-',
      file->fsstat.mode & 04 ? 'r' : '-',
      file->fsstat.mode & 02 ? 'w' : '-',
      file->fsstat.mode & 01 ? 'x' : '-',
      file->fsstat.file_size, file->path);
}

int
main (int argc, char *argv[])
{
  int i;

  if (argc < 2)
    die (USAGE_STRING, argv[0]);

  for (i = 1; i < argc; i++) {
    if (strcasecmp (argv[i], "SetKeysFile") == 0) {
      /* SetKeysFile filename */
      if (i + 1 >= argc)
        die (USAGE_STRING "Not enough arguments to command\n", argv[0]);
      keys_set_path (argv[++i]);
    } else if (strcasecmp (argv[i], "SetDeviceID") == 0 ||
        strcasecmp (argv[i], "SetPSID") == 0) {
      /* SetDeviceID (HEX|filename) */
      /* SetPSID (HEX|filename) */
      u8 id[0x10];

      if (i + 1 >= argc)
        die (USAGE_STRING "Not enough arguments to command\n", argv[0]);

      if (file_exists (argv[i+1])) {
        FILE *f = fopen (argv[i+1], "rb");
        if (fread (id, 0x10, 1, f) != 1)
          die ("Unable to read ID from file\n");
        fseek (f, 0, SEEK_END);
        if (ftell (f) != 16)
          die ("ID file must be exactly 16 bytes\n");
        fclose (f);
      } else {
        if (strlen (argv[i+1]) != 32)
          die ("ID must be 16 bytes and in hex format or a filename\n");
        if (parse_hex (argv[i+1], id, 16) != 16)
          die ("ID must be in hex format or a filename\n");
      }
      if (strcasecmp (argv[i], "SetDeviceID") == 0)
        archive_set_device_id (id);
      else
        archive_set_open_psid (id);
      i++;
    }  else if (strcasecmp (argv[i], "ExtractPSID") == 0) {
      /* ExtractPSID backup_dir output */
      ArchiveIndex archive;
      char path[1024];
      FILE *f = NULL;

      if (i + 2 >= argc)
        die (USAGE_STRING "Not enough arguments to command\n", argv[0]);

      snprintf (path, sizeof(path), "%s/archive.dat", argv[i+1]);
      if (!archive_index_read (&archive, path))
        die ("Error parsing archive index!\n");

      f = fopen (argv[i+2], "wb");
      if (fwrite (archive.footer.psid, 0x10, 1, f) != 1)
        die ("Unable to write ID from file\n");
      fclose (f);

      i += 2;
    } else if (strcasecmp (argv[i], "ReadIndex") == 0) {
      /* ReadIndex archive.dat */
      ArchiveIndex archive_index;

      if (i + 1 >= argc)
        die (USAGE_STRING "Not enough arguments to command\n", argv[0]);
      i++;

      if (!archive_index_read (&archive_index, argv[i]))
        die ("Error parsing archive index!\n");
      printf ("Files : \n");
      chained_list_foreach (archive_index.files,
          (ChainedListForeachCallback) archive_print_file, (void *) "    ");
      printf ("Directories : \n");
      printf ("   |\n");
      chained_list_foreach (archive_index.dirs,
          (ChainedListForeachCallback) archive_print_dir, (void *) "   |_ ");
      printf ("Backup id : ");
      print_hash ((u8 *) &archive_index.header.id, 8);
      printf ("\nTotal files : %" U64_FORMAT "\n", archive_index.total_files);
      printf ("Total directories : %" U64_FORMAT "\n", archive_index.total_dirs);
      printf ("Total archive size : %" U64_FORMAT " bytes\n", archive_index.total_file_sizes);
      if (archive_index.header.archive_type == 5) {
        printf ("Your Open PSID : ");
        print_hash (archive_index.footer.psid, 16);
        printf ("\nTotal filesize of the copy-protected content : %" U64_FORMAT " bytes\n",
            archive_index.footer.archive2_size);
      }
      archive_index_free (&archive_index);
    } else if (strcasecmp (argv[i], "ReadData") == 0) {
      /* ReadData archive_XX.dat */
      ArchiveData archive_data;

      if (i + 1 >= argc)
        die (USAGE_STRING "Not enough arguments to command\n", argv[0]);
      i++;

      if (!archive_data_read (&archive_data, argv[i]))
        die ("Error parsing archive data!\n");
      printf ("Backup id : ");
      print_hash ((u8 *) &archive_data.header.id, 8);
      printf ("\nData archive index : %d\n", archive_data.header.index);
      printf ("Backup file type : %d\n", archive_data.header.file_type);
      printf ("Backup type : %d\n", archive_data.header.archive_type);
    } else if (strcasecmp (argv[i], "Decrypt") == 0) {
      /* Decrypt archive[_XX].dat decrypted.dat */
      if (i + 2 >= argc)
        die (USAGE_STRING "Not enough arguments to command\n", argv[0]);

      if (!archive_decrypt (argv[i+1], argv[i+2]))
        die ("Error decrypting archive!\n");

      i += 2;
    } else if (strcasecmp (argv[i], "Dump") == 0) {
      /* Dump backup_dir destination_dir */
      if (i + 2 >= argc)
        die (USAGE_STRING "Not enough arguments to command\n", argv[0]);

      if (!archive_dump_all (argv[i+1], argv[i+2]))
        die ("Error dumping backup!\n");

      i += 2;
    } else if (strcasecmp (argv[i], "ExtractFile") == 0) {
      /* ExtractFile backup_dir filename destination */
      if (i + 3 >= argc)
        die (USAGE_STRING "Not enough arguments to command\n", argv[0]);

      if (!archive_extract_file (argv[i+1], argv[i+2], argv[i+3]))
        die ("Unable to extract file\n");

      i += 3;
    } else if (strcasecmp (argv[i], "ExtractPath") == 0) {
      /* ExtractPath backup_dir path destination_dir */
      if (i + 3 >= argc)
        die (USAGE_STRING "Not enough arguments to command\n", argv[0]);

      if (!archive_extract_path (argv[i+1], argv[i+2], argv[i+3]))
        die ("Unable to extract path\n");

      i += 3;
    } else if (strcasecmp (argv[i], "DeleteFile") == 0) {
      /* DeleteFile backup_dir filename */
      if (i + 2 >= argc)
        die (USAGE_STRING "Not enough arguments to command\n", argv[0]);

      archive_rename_file (argv[i+1], argv[i+2], "/dev_hdd0/tmp/null");

      i += 2;
    } else if (strcasecmp (argv[i], "DeletePath") == 0) {
      /* DeletePath backup_dir path */
      if (i + 2 >= argc)
        die (USAGE_STRING "Not enough arguments to command\n", argv[0]);

      archive_rename_path (argv[i+1], argv[i+2], "/dev_hdd0/tmp/null");

      i += 2;
    } else if (strcasecmp (argv[i], "DeleteProtected") == 0) {
      /* DeleteProtected backup_dir */
      if (i + 1 >= argc)
        die (USAGE_STRING "Not enough arguments to command\n", argv[0]);

      archive_delete_protected (argv[i+1]);

      i++;
    } else if (strcasecmp (argv[i], "Add") == 0) {
      /* Add backup_dir directory */
      if (i + 2 >= argc)
        die (USAGE_STRING "Not enough arguments to command\n", argv[0]);

      if (!archive_add (argv[i+1], argv[i+2], FALSE))
        die ("Error adding directory to backup!\n");

      i += 2;
    } else if (strcasecmp (argv[i], "AddProtected") == 0) {
      /* AddProtected backup_dir directory */

      if (i + 2 >= argc)
        die (USAGE_STRING "Not enough arguments to command\n", argv[0]);

      /* Add the dir to the backup */
      if (!archive_add (argv[i+1], argv[i+2], TRUE))
        die ("Error adding directory to backup!\n");

      i += 2;
    } else if (strcasecmp (argv[i], "CreateBackup") == 0) {
      /* ExtractFile backup_dir filename destination */
      if (i + 3 >= argc)
        die (USAGE_STRING "Not enough arguments to command\n", argv[0]);

      if (file_exists (argv[i+1]))
          die ("Backup dir must not exist in order to create a new one\n");

      if (!archive_create_backup (argv[i+1], argv[i+2], argv[i+3]))
        die ("Unable to create backup\n");

      i += 3;
    } else {
      die (USAGE_STRING "Error: Unknown command\n", argv[0]);
    }
  }

  keys_free (keys, num_keys);
  return 0;
}

