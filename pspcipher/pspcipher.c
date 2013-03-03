/*
 * This file is part of pspcipher.
 *
 * Copyright (C) 2008 hrimfaxi (outmatch@gmail.com)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <malloc.h>

#include "utils.h"
#include "kirk_engine.h"
#include "pspcipher.h"
#include "psp_headers.h"

#define SAFE_FREE(p) do { \
	if ((p) != NULL) { free(p); (p) = NULL; }  \
} while ( 0 );

typedef struct {
	u32 tag;
	u8 *key;
	u32 code;
	u32 type;
} CipherKey;

#include "keys_data.h"

CipherKey *GetCipherByTag(u32 tag)
{
	int i;

	for(i=0; i<NELEMS(g_cipher); ++i) {
		if (g_cipher[i].tag == tag)
			return &g_cipher[i];
	}

	return NULL;
}

int WriteFile(const char *file, void *buf, int size)
{
	FILE *fp;
	int written;

	fp = fopen(file, "wb");

	if(fp==NULL) {
		return -1;
	}

	written = fwrite(buf, 1, size, fp);

	if (written != size) {
		fclose(fp);

		return -2;
	}

	fclose(fp);

	return written;
}

void ErrorExit(char *fmt, ...)
{
	va_list list;
	char msg[256];	

	va_start(list, fmt);
	vsnprintf(msg, sizeof(msg), fmt, list);
	msg[sizeof(msg)-1] = '\0';
	va_end(list);

	printf(msg);
	exit(-1);	
}

void DispPrxInfo(const char *filename, u8 *prx)
{
	PSP_Header2 *header;

	header = (PSP_Header2*)prx;

	printf("\n%s:\n", filename);
	printf("\tname: %.28s", header->modname);
	printf(", elf_size: %d", header->elf_size);
	printf(", decrypt_mode: 0x%X", header->decrypt_mode);
	printf(", tag: 0x%08X\n", header->tag);
	printf("\n");
}

int IsPrxCompressed(u8 *prx)
{
	if ((prx[0] == 0x1F && prx[1] == 0x8B) ||
		   	memcmp(prx, "2RLZ", 4) == 0 ||
		   	memcmp(prx, "KL4E", 4) == 0) {
		return 1;
	}
	
	return 0;
}

int CipherDecrypt(u8 *prx, u32 size, const char *output_filename)
{
	int ret; 
	u32 cbDecrypted = 0;
	u32 tag;
	user_decryptor u_dec;

	tag = ((PSP_Header2*)prx)->tag;
	CipherKey *cipher = GetCipherByTag(tag);

	if (cipher == NULL) {
		printf("Unknown key tag: 0x%08x\n", tag);

		return -1;
	}

	u_dec.tag = &tag;
	u_dec.key = cipher->key;
	u_dec.code = cipher->code;
	u_dec.prx = prx;
	u_dec.size  = size;
	u_dec.newsize = &cbDecrypted;
	u_dec.use_polling = 0;
	u_dec.blacklist = NULL;
	u_dec.blacklistsize = 0;
	u_dec.type = cipher->type;
	u_dec.xor_key1 = NULL;
	u_dec.xor_key2 = NULL;
	ret = uprx_decrypt(&u_dec);

	if (ret != 0) {
		printf("uprx_decrypt failed -> %d\n", ret);

		return ret;
	} else {
		printf("Decrypt OK, ");
	}

	if (IsPrxCompressed(prx)) {
		printf("Decompress not implenment yet\n");
	}

	ret = WriteFile(output_filename, prx, cbDecrypted);

	if (ret != cbDecrypted) {
		ErrorExit("Error writing %s (%d)\n", output_filename, ret);
	} else {
		printf("%s saved\n", output_filename);
	}

	return 0;
}

void PrintUsage(int argc, char *argv[])
{
	printf("%s: <input_eboot_bin> <output_eboot_bin>\n", argv[0]);
}

int LoadFile(const char *src, u8 **output_buf, long *file_size)
{
	FILE *fp;
	void *buf;

	fp = fopen(src, "rb");

	if (fp == NULL) {
		return -1;
	}

	fseek(fp, 0, SEEK_END);
	*file_size = ftell(fp);
	buf = malloc(*file_size);

	if (buf == NULL) {
		fclose(fp);

		return -2;
	}

	fseek(fp, 0, SEEK_SET);
	
	if (1 != fread(buf, *file_size, 1, fp)) {
		fclose(fp);
		free(buf);
		
		return -3;
	}

	*output_buf = buf;
	fclose(fp);

	return 0;
}

u8 *CheckPrxHeader(u8 *file, int file_size)
{
	u32 *header;

	if (file_size < 0x160) {
		return NULL;
	}

	for (header = (u32*)file; header < (u32*)(file+file_size); ++header) {
		if (*header == 0x5053507e /* ~PSP */ ) {
			break;
		}
	}

	if (header >= (u32*)(file+file_size)) {
		return NULL;
	}

	return (u8*)header;
}

int main(int argc, char *argv[])
{
	u8 *prx_file = NULL, *prx = NULL;
	const char *src, *dst;
	long file_size;
	int ret;
	
	kirk_init();
	src = dst = NULL;

	if (argc < 3) {
		PrintUsage(argc, argv);

		return -1;
	} else {
		src = argv[1];
		dst = argv[2];
	}

	printf("PSPCipher by TPU & liquidzigong\n");
	ret = LoadFile(src, &prx_file, &file_size);

	if (ret < 0) {
		ErrorExit("Load file failed (%d)\n", ret);
	}

	prx = CheckPrxHeader(prx_file, file_size);

	if (prx == NULL) {
		ErrorExit("Invalid PRX\n");
	}

	DispPrxInfo(src, prx);
	CipherDecrypt(prx, file_size, dst);
	SAFE_FREE(prx_file);

    return 0;
}
