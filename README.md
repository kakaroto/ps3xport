PS3xport : PS3/EXPORT Backup Manipulation Utility
---

PS3xport is a utility for manipulating PS3 Backup archives. It can create a fully working backup from scratch, as well as extract files from existing backups or rename, delete or add new files to an existing backup.

# PS3 Backup files
A PS3 Backup is created from the `System Settings -> Backup Utility -> Backup` menu on the XMB. It requires the use of a FAT32 formatted hard drive and it will create the backup as a subdirectory of the directory *PS3/EXPORT/* named with the current date and time. For example : *D:/PS3/EXPORT/201412242359*

The Backup directory will contain the following files : 

* archive.dat - This will be the "**Index** file" for your backup
* archive_00.dat, archive_01.dat, archive_02.dat, etc.. - These are the "**Data** files" for your backup
* archive2.dat - This will be the "**Index** file" of your copy-protected files
* archive2_00.dat, archive2_01.dat, archive2_02.dat, etc.. - These are the "**Data** files" for your copy-protected data

As you can see, there are two types of files, **Index** files and **Data** files. The Index files will contain the list of all the files and directories in the Data files while the Data files will only contain data. There are also two types of backups, regular files and copy-protected files. The copy-protected files are for your PSN games, copy-protected save files and the like. The copy-protected files are encrypted with your unique PS3 device ID so they cannot be decrypted on another PS3. 
The archive.dat files will not be encrypted with your PS3's *Device ID* so they can be restored on any PS3. However, the file does contain your *OpenPSID* which tells the PS3 from which console the backup was created. Not having the right PSID set in a backup has little significance, other than the fact that when restoring it, the PS3 will show a warning about the backup being restored from a different PS3.

# Tool Usage
PS3xport takes commands as arguments and multiple commands can be chained together in a single call.

Here is the usage of the tool :

    Usage: ps3xport command [argument ...] [command ...]
      Commands : 
	  SetKeysFile filename:
		  Set the path to the keys.conf file  (default: keys.conf)
	  SetDeviceID (HEX|filename):
		  Set the DeviceID needed for decrypting archive2.dat
	  SetPSID (HEX|filename):
		  Set the OpenPSID needed for creating new backups
	  ExtractPSID backup_dir output:
		  Extract the OpenPSID from a backup directory
	  ReadIndex archive.dat:
		  Parse the specified index file and print info
	  ReadData archive_XX.dat:
		  Parse the specified data file and print info
	  Decrypt archive[_XX].dat decrypted.dat:
		  Decrypt the given .dat file
	  Dump backup_dir destination_dir:
		  Extract the whole backup to the destination directory
	  ExtractFile backup_dir filename destination:
		  Extract from a backup a specific file
	  ExtractPath backup_dir path destination_dir:
		  Extract from a backup all files matching the specified path
	  DeleteFile backup_dir filename:
		  Delete from a backup a specific file
	  DeletePath backup_dir path:
		  Delete from a backup all files matching the specified path
	  DeleteProtected backup_dir
		  Deletes the copy-protected files from the backup
	  Add backup_dir directory:
		  Add the given directory and subdirs to the backup
	  AddProtected backup_dir directory:
		  Add the given directory and subdirs to the copy-protected backup
	  CreateBackup backup_dir content protected_content
		  Create a new backup with a content dir and a copy-protected content
		    Set the content path to '-' to ignore it


The tool needs access to the PS3 keys in order to function. You can give it the path of the *keys.conf* file using the **SetKeysFile** command. If it is not specified, then the tool will first look for the *keys.conf* file in the current directory, then in the directory defined by the environment variable __*PS3\_KEYS\_PATH*__ if it exists, then in the `.ps3` directory in the home directory. The keys.conf file needs to have a key of type '**sc**' with revision 3.

You can set the Device ID with the **SetDeviceID** command and give it the Device ID (also known as IDP) either as a hex string or by specifying the filename to a 16-byte binary file containing the device id. The same can also be used for setting the OpenPSID of the console with the **SetPSID** command.

If you need to find the OpenPSID of your console, you can simply create a backup and use the **ExtractPSID** command, specifying the backup directory and a filename to which to write the PSID as a binary file.

Note that those settings are not permanent, so for them to be used by the tool, they need to precede another command which requires them. See examples for more information.

You can use the **ReadIndex** and **ReadData** commands to read the **Index** (archive.dat or archive2.dat) and **Data** files (archive_XX.dat or archive2_XX.dat) and print information about them. Using the **ReadIndex** command will list all the files and directories in the index file with their full path, sizes and permissions, etc.. as well as any additional data available in the index file, such as the backup's unique ID, the console's PSID, the size of the copy-protected data, etc.. Using the **ReadData** command will simply output the backup's unique ID, the index of the data file (the files must be sequential), and will make sure that the files are not corrupted by hashing the entire data file. Note that for Copy-Protected files (archive2[_XX].dat), the DeviceID must be set.

The **Decrypt** command can be useful for debugging a file or for better understanding the file format. It will simply take a .dat file and decrypt it for you, either using a PS3 static key for archive.dat files or the Device ID for archive2.dat files.

The **Dump** command will extract an entire backup to the given destination directory. Note that in order to extract copy-protected content, you need to set the DeviceID first. If you wish to extract only a specific file, you can instead use the **ExtraFile** command and specify the file you want extracted. For even more freedom you can also use the **ExtractPath** command which will extract every file and directory which matches the path specified.

To delete a file from a backup, use the **DeleteFile** or **DeletePath** commands. They will basically just rename the file into the /dev_hdd0/tmp/null file as deleting a file would require the regeneration of the entire backup file.

The **DeleteProtected** command however will affect the archive.dat file so it acts as if there is no archive2.dat file that comes with it, thus removing the copy-protected content from the backup. This will mostly have the effect of disabling the warning on the PS3 when the backup is restored on a different PS3 that some of the data could not be restored.

To add new files to the backup, use the *Add* and *AddProtected** commands. They will recursively add all the files specified to the backup. You can also create a backup from scratch with the **CreateBackup** command, giving it the backup directory to create, the directory for the content and for the copy-protected content. You can set either one of the directories to `-` in order to ignore that directory.

# Examples

To get your OpenPSID, you can do :

```./ps3xport ExtractPSID PS3/EXPORT/201412242359/ psid.bin```

To show the list of non-protected files in a backup, type :

```./ps3xport ReadIndex PS3/EXPORT/201412242359/archive.dat```

To show the list of protected files in a backup, type :

```./ps3xport SetDeviceID idp.bin ReadIndex PS3/EXPORT/201412242359/archive2.dat```

To list every files in the backup and write it to a text file, type :

```./ps3xport SetDeviceID idp.bin ReadIndex PS3/EXPORT/201412242359/archive.dat ReadIndex PS3/EXPORT/201412242359/archive2.dat > filelist.txt```

To create a new simple backup without copy-protected content:

```./ps3xport SetPSID psid.bin CreateBackup PS3/EXPORT/MYBACKUP my_custom_dev_hdd0 -```

or with copy-protected data :

```./ps3xport SetPSID psid.bin SetDeviceID idp.bin CreateBackup PS3/EXPORT/MYBACKUP my_custom_dev_hdd0 my_protected_data```

To add new files to a backup :

```./ps3xport Add PS3/EXPORT/MYBACKUP dev_flash2```

You can also chain multiple operations in a single command :

```./ps3xport ExtractPSID PS3/EXPORT/201412242359/ psid.bin SetPSID psid.bin ExtractPath PS3/EXPORT/201412242359/ /dev_flash2 output_dev_flash2 SetDeviceID idp.bin CreateBackup PS3/EXPORT/MYBACKUP my_custom_dev_hdd0 my_protected_data Add PS3/EXPORT/MYBACKUP output_dev_flash2 DeleteProtected PS3/EXPORT/201412242359```