/*

Copyright 2015 Kakaroto

This software is distributed under the terms of the GNU General Public
License ("GPL") version 3, as published by the Free Software Foundation.

*/

#ifndef __VTRM_H__
#define __VTRM_H__

#include "tools.h"
#include "types.h"
#include "common.h"
#include "keys.h"

extern Key *keys;
extern int num_keys;

void vtrm_encrypt_with_portability (u32 type, u8 *buffer, u8 *iv);
void vtrm_encrypt (u32 type, u8 *buffer, u8 *iv);
void vtrm_encrypt_master (u64 laid, u64 paid, u8 *buffer, u8 *iv);

void vtrm_decrypt_with_portability (u32 type, u8 *buffer, u8 *iv);
void vtrm_decrypt (u32 type, u8 *buffer, u8 *iv);
void vtrm_decrypt_master (u64 laid, u64 paid, u8 *buffer, u8 *iv);

#endif /* __VTRM_H__ */
