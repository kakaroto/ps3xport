// 2011 Ninjas
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt

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

#define PS3XPORT_VERSION "0.1"

#define USAGE_STRING "PS3xport v" PS3XPORT_VERSION "\n"                 \
  "  Usage: %s command [argument ...] [command ...]\n"                  \
  "    Commands : \n"                                                   \
  "\t  SetKeysFile filename:\n"                                         \
  "\t\t  Set the path to the keys.conf file  (default: keys.conf)\n"    \
  "\t  SetDeviceID (HEX|filename):\n"                                   \
  "\t\t  Set the DeviceID needed for decrypting archive2.dat\n"         \
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
  "\t  DeletePath backup_dir path:\n"                   \
  "\t\t  Delete from a backup all files matching the specified path\n"  \
  "\t  Add backup_dir directory:\n"                                     \
  "\t\t  Add the given directory and subdirs to the backup\n"           \
  "\t  AddProtected backup_dir directory:\n"                            \
  "\t\t  Add the given directory and subdirs to the copy-protected backup\n\n"

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
    if (strcmp (argv[i], "SetKeysFile") == 0) {
      /* SetKeysFile filename */
      if (i + 1 >= argc)
        die (USAGE_STRING "Not enough arguments to command\n", argv[0]);
      keys_conf_path = argv[++i];
    } else if (strcmp (argv[i], "SetDeviceID") == 0) {
      /* SetDeviceID (HEX|filename) */
      int j;
      u8 device_id[0x10];

      if (i + 1 >= argc)
        die (USAGE_STRING "Not enough arguments to command\n", argv[0]);
      i++;
      if (file_exists (argv[i])) {
        FILE *f = fopen (argv[i], "rb");
        if (fread (device_id, 0x10, 1, f) != 1)
          die ("Unable to read DeviceID from file\n");
        fseek (f, 0, SEEK_END);
        if (ftell (f) != 16)
          die ("IDP file must be exactly 16 bytes\n");
        fclose (f);
      } else {
        if (strlen (argv[i]) != 32)
          die ("Device ID must be 16 bytes and in hex format or a filename\n");
        if (parse_hex (argv[i], device_id, 16) != 16)
          die ("Device ID must be in hex format or a filename\n");
      }

      archive_set_device_id (device_id);
      DBG ("Device ID set to : ");
      print_hash (device_id, 16);
      DBG ("\n");
    } else if (strcmp (argv[i], "ReadIndex") == 0) {
      /* ReadIndex archive.dat */
      ArchiveIndex archive_index;

      if (i + 1 >= argc)
        die (USAGE_STRING "Not enough arguments to command\n", argv[0]);
      i++;

      if (!index_archive_read (&archive_index, argv[i]))
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
      printf ("\nTotal files : %llu\n", archive_index.total_files);
      printf ("Total directories : %llu\n", archive_index.total_dirs);
      printf ("Total archive size : %llu bytes\n", archive_index.total_file_sizes);
      if (archive_index.header.archive_type == 5) {
        printf ("Your Open PSID : ");
        print_hash (archive_index.footer.psid, 16);
        printf ("\nTotal filesize of the copy-protected content : %llu bytes\n",
            archive_index.footer.archive2_size);
      }
    } else if (strcmp (argv[i], "ReadData") == 0) {
      /* ReadData archive_XX.dat */
      ArchiveData archive_data;

      if (i + 1 >= argc)
        die (USAGE_STRING "Not enough arguments to command\n", argv[0]);
      i++;

      if (!data_archive_read (&archive_data, argv[i]))
        die ("Error parsing archive data!\n");
      printf ("Backup id : ");
      print_hash ((u8 *) &archive_data.header.id, 8);
      printf ("\nData archive index : %d\n", archive_data.header.index);
      printf ("Backup id type : %d\n", archive_data.header.id_type);
      printf ("Backup type : %d\n", archive_data.header.archive_type);
    } else if (strcmp (argv[i], "Decrypt") == 0) {
      /* Decrypt archive[_XX].dat decrypted.dat */
      if (i + 2 >= argc)
        die (USAGE_STRING "Not enough arguments to command\n", argv[0]);

      if (!archive_decrypt (argv[i+1], argv[i+2]))
        die ("Error decrypting archive!\n");

      i += 2;
    } else if (strcmp (argv[i], "Dump") == 0) {
      /* Dump backup_dir destination_dir */
      if (i + 2 >= argc)
        die (USAGE_STRING "Not enough arguments to command\n", argv[0]);

      if (!archive_dump_all (argv[i+1], argv[i+2]))
        die ("Error dumping backup!\n");

      i += 2;
    } else if (strcmp (argv[i], "ExtractFile") == 0) {
      /* ExtractFile backup_dir filename destination */
      if (i + 3 >= argc)
        die (USAGE_STRING "Not enough arguments to command\n", argv[0]);

      if (!archive_extract_file (argv[i+1], argv[i+2], argv[i+3]))
        die ("Unable to extract file\n");

      i += 3;
    } else if (strcmp (argv[i], "ExtractPath") == 0) {
      /* ExtractPath backup_dir path destination_dir */
      if (i + 3 >= argc)
        die (USAGE_STRING "Not enough arguments to command\n", argv[0]);

      if (!archive_extract_path (argv[i+1], argv[i+2], argv[i+3]))
        die ("Unable to extract path\n");

      i += 3;
    } else if (strcmp (argv[i], "DeleteFile") == 0) {
      /* DeleteFile backup_dir filename */
      if (i + 2 >= argc)
        die (USAGE_STRING "Not enough arguments to command\n", argv[0]);

      archive_rename_file (argv[i+1], argv[i+2], "/dev_hdd0/tmp/null");

      i += 2;
    } else if (strcmp (argv[i], "DeletePath") == 0) {
      /* DeletePath backup_dir path */
      if (i + 2 >= argc)
        die (USAGE_STRING "Not enough arguments to command\n", argv[0]);

      archive_rename_path (argv[i+1], argv[i+2], "/dev_hdd0/tmp/null");

      i += 2;
    } else if (strcmp (argv[i], "Add") == 0) {
      /* Add backup_dir directory */
      if (i + 2 >= argc)
        die (USAGE_STRING "Not enough arguments to command\n", argv[0]);

      if (!archive_add (argv[i+1], argv[i+2], FALSE))
        die ("Error adding directory to backup!\n");

      i += 2;
    } else if (strcmp (argv[i], "AddProtected") == 0) {
      /* AddProtected backup_dir directory */
      ArchiveIndex archive;
      ArchiveIndex archive2;
      char path[1024];

      if (i + 2 >= argc)
        die (USAGE_STRING "Not enough arguments to command\n", argv[0]);

      /* Add the dir to the backup */
      if (!archive_add (argv[i+1], argv[i+2], TRUE))
        die ("Error adding directory to backup!\n");

      /* Read archive2.dat and archive.dat */
      snprintf (path, sizeof(path), "%s/archive2.dat", argv[i+1]);
      if (!index_archive_read (&archive2, path))
        die ("Error parsing archive index!\n");
      snprintf (path, sizeof(path), "%s/archive.dat", argv[i+1]);
      if (!index_archive_read (&archive, path))
        die ("Error parsing archive index!\n");

      /* Fix the footer from archive.dat */
      archive.footer.archive2_size = archive.total_file_sizes;
      if (!index_archive_write (&archive, path))
        die ("Error parsing archive index!\n");

      i += 2;
    } else {
      die (USAGE_STRING "Error: Unknown command\n", argv[0]);
    }
  }

  keys_free (keys, num_keys);
  return 0;
}

