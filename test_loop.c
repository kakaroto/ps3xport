/*

Copyright 2015 Kakaroto

This software is distributed under the terms of the GNU General Public
License ("GPL") version 3, as published by the Free Software Foundation.

*/

#include <ppu-lv2.h>
#include <stdio.h>
#include <string.h>

static void hex_dump(void *data, int size);
typedef struct { u64 high; u64 low;} CellSsOpenPSID;

s32 get_ps_id (CellSsOpenPSID *v) {
  lv2syscall1 (872, (u64)v);
  return_to_user_prog(s32);
}

s32 get_device_id (char *v) {
  lv2syscall2 (867, 0x19003, (u64)v);
  return_to_user_prog(s32);
}

s32 encrypt_with_portability (int mode, char *iv, char *data) {
  lv2syscall5 (862, 0x200C, mode, (u64)iv, (u64)data, 0);
  return_to_user_prog(s32);
}

s32 encrypt (int mode, char *iv, char *data) {
  lv2syscall5 (862, 0x200A, mode, (u64)iv, (u64)data, 0);
  return_to_user_prog(s32);
}

int main () {
  s32 i=0;
  s32 ret;

  char data[64];
  char iv[16];
  char seed[20];
  char id[16];

  memset(data, 0, 64);
  memset(iv, 0, 64);
  memset(seed, 0, 20);
  memset(id, 0, 16);

  CellSsOpenPSID psid;

/*
  ret = get_ps_id (&psid);
  printf ("PSID = %X\n", ret);
  hex_dump (&psid, 16);

  ret = get_device_id (id);
  printf ("DEVICE ID = %X\n", ret);
  hex_dump (id, 16);
*/

  printf ("\n\n\n");

  for (i=0; i <= 3; i++ )
  {
    memset(data, 0, 64);
    memset(iv, 0, 16);
	
/*
    printf ("IN DATA:\n");
    hex_dump(data, 64);
    printf ("IN IV:\n");
    hex_dump(iv, 16);
*/

    ret = encrypt_with_portability (i, iv, data);
    printf ("ret = %X\n", ret);
    printf ("encrypt_with_portability type %d\n", i);
    printf ("OUT DATA:\n");
    hex_dump (data, 64);
    printf ("OUT IV:\n");
    hex_dump (iv, 16);
    printf ("\n");
  }

  for (i=0; i <= 3; i++ )
  {
    memset(data, 0, 64);
    memset(iv, 0, 16);
	
/*
    printf ("IN DATA:\n");
    hex_dump(data, 64);
    printf ("IN IV:\n");
    hex_dump(iv, 16);
*/

    ret = encrypt (i, iv, data);
    printf ("ret = %X\n", ret);
    printf ("encrypt type %d\n", i);
    printf ("OUT DATA:\n");
    hex_dump (data, 64);
    printf ("OUT IV:\n");
    hex_dump (iv, 16);
    printf ("\n");
  }

  return 0;
}

static void hex_dump(void *data, int size)
{
    /* dumps size bytes of *data to stdout. Looks like:
     * [0000] 75 6E 6B 6E 6F 77 6E 20
     *                  30 FF 00 00 00 00 39 00 unknown 0.....9.
     * (in a single line of course)
     */

    unsigned char *p = data;
    unsigned char c;
    int n;
    char bytestr[6] = {0};
    char addrstr[10] = {0};
    char hexstr[ 16*6 + 5] = {0};
    char charstr[16*1 + 5] = {0};
    for(n=1;n<=size;n++) {
        if (n%16 == 1) {
			
            /* Store address for this line */
			
            snprintf(addrstr, sizeof(addrstr), "%.4x",
               ((unsigned int)p-(unsigned int)data) );
        }
            
        c = *p;
        if (isalnum(c) == 0) {
            c = '.';
        }

        /* Store hex str (for left side) */
		
        snprintf(bytestr, sizeof(bytestr), "0x%02X, ", *p);
        strncat(hexstr, bytestr, sizeof(hexstr)-strlen(hexstr)-1);

        /* Store char str (for right side) */
		
        snprintf(bytestr, sizeof(bytestr), "%c", c);
        strncat(charstr, bytestr, sizeof(charstr)-strlen(charstr)-1);

        if(n%16 == 0) { 
		
            /* Line completed */
			
            printf("%-90.90s\n", hexstr );
            hexstr[0] = 0;
            charstr[0] = 0;
        } else if(n%8 == 0) {
			
            /* Half line: add white spaces */
			
            strncat(hexstr, "  ", sizeof(hexstr)-strlen(hexstr)-1);
            strncat(charstr, " ", sizeof(charstr)-strlen(charstr)-1);
        }
        p++; /* Next byte */
    }

    if (strlen(hexstr) > 0) {
		
        /* Print rest of buffer if not empty */
		
        printf("%-90.90s\n", hexstr );
    }
}
