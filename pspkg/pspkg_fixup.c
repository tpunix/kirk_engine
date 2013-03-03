/*
 * pspkg.c
 *    psp/ps3 pkg extractor.
 *    writen by tpu.
 *    port from Mathieulh's C# source
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/stat.h>

#include "kirk_engine.h"
#include "crypto.h"

/*************************************************************/

u8 psp_pkg_key[16] = {0x07,0xF2,0xC6,0x82,0x90,0xB5,0x0D,0x2C,0x33,0x81,0x8D,0x70,0x9B,0x60,0xE6,0x2B};
u8 ps3_pkg_key[16] = {0x2E,0x7B,0x71,0xD7,0xC9,0xC9,0xA1,0x4E,0xA3,0x22,0x1F,0x18,0x88,0x28,0xB8,0xF8};


u32 get_be64(u8 *buf)
{
	return (u32)( (buf[0]<<24) | (buf[1]<<16) | (buf[2]<<8) | buf[3]);
}

u32 get_be32(u8 *buf)
{
	return (u32)( (buf[0]<<24) | (buf[1]<<16) | (buf[2]<<8) | buf[3]);
}

/*************************************************************/

void xor_key(u8 *dst, u8 *src, int len)
{
	int i;

	for(i=0; i<len; i++){
		dst[i] ^= src[i];
	}
}

void key_inc(u8 *key, int pos)
{
	if(key[pos]==0xff){
		key[pos] = 0;
		key_inc(key, pos-1);
	}else{
		key[pos] += 1;
	}
}

/* aes_ctr_encrypt */
void aes_ctr_encrypt(u8 *data, int size, int offset, u8 *file_key, u8 *aes_key)
{
	AES_ctx cpkg;
	u8 ikey[16], xkey[16];
	int i;

	AES_set_key(&cpkg, aes_key, 128);
	memcpy(ikey, file_key, 16);

	for(i=0; i<offset; i+=16){
		key_inc(ikey, 15);
	}

	for(i=0; i<size; i+=16){
		memcpy(xkey, ikey, 16);
		AES_encrypt(&cpkg, xkey, xkey);
		xor_key(data+i, xkey, 16);
		key_inc(ikey, 15);
	}
}

void sha1_ctr_encrypt(u8 *data, int size, int offset, u8 *sha1_key)
{
	u8 ikey[0x40], xkey[0x14];
	int i;

	memcpy(ikey, sha1_key, 0x40);

	for(i=0; i<offset; i+=16){
		key_inc(ikey+0x38, 7);
	}

	for(i=0; i<size; i+=16){
		SHA1(ikey, 0x40, xkey);
		xor_key(data+i, xkey, 16);
		key_inc(ikey+0x38, 7);
	}
}

/*************************************************************/


int fixup_pkg(char *pkg_name, char *new_name)
{
	FILE *fp;
	u8 header[256], file_key[16], sha1_key[0x40];
	u8 *pkg_buf, *pkg_aeskey, *file_table;
	int i, base, data_size, pkg_size, total_file;

	fp = fopen(pkg_name, "rb");

	/* header check */
	fread(header, 256, 1, fp);
	if(*(u32*)(header)!=0x474b507f){
		printf("Selected file isn't a PKG file!\n");
		return -1;
	}
	if(header[4]==0x80){
		printf("Selected file isn't a debug PKG.\n");
		return -1;
	}

	pkg_aeskey = psp_pkg_key;

	/* read all file */
	fseek(fp, 0, SEEK_END);
	pkg_size = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	pkg_buf = malloc(pkg_size);
	fread(pkg_buf, pkg_size, 1, fp);
	fclose(fp);

	/* make sha1 key */
	memset(sha1_key, 0, 0x40);
	memcpy(sha1_key+0x00, pkg_buf+0x60, 8);
	memcpy(sha1_key+0x08, pkg_buf+0x60, 8);
	memcpy(sha1_key+0x10, pkg_buf+0x68, 8);
	memcpy(sha1_key+0x18, pkg_buf+0x68, 8);

	base = get_be32(pkg_buf+0x24);
	data_size = get_be32(pkg_buf+0x2c);
	total_file = get_be32(pkg_buf+0x14);

	// decrypt debug pkg
	sha1_ctr_encrypt(pkg_buf+base, data_size, 0, sha1_key);



	memcpy(file_key, header+0x70, 0x10);

	// read file table
	file_table = malloc(total_file*0x20);
	memcpy(file_table, pkg_buf+base, total_file*0x20);

	// encrypt file table
	aes_ctr_encrypt(pkg_buf+base, total_file*0x20, 0, file_key, pkg_aeskey);

	// process all file
	for(i=0; i<total_file; i++){
		u8 *desc = file_table+i*0x20;
		int name_offset = get_be32(desc+0x00);
		int name_length = get_be32(desc+0x04);
		int file_offset = get_be32(desc+0x0c);
		int file_length = get_be32(desc+0x14);
		int content_type= desc[0x18];
		int file_type   = desc[0x1b];
		u8 content_name[64];

		// read name
		memcpy(content_name, pkg_buf+base+name_offset, name_length);
		content_name[name_length] = 0;

		// encrypt name
		if(content_type==0x90){
			pkg_aeskey = psp_pkg_key;
		}else{
			pkg_aeskey = ps3_pkg_key;
		}
		aes_ctr_encrypt(pkg_buf+base+name_offset, name_length, name_offset, file_key, pkg_aeskey);

		printf("file %2d: offset=%08x length=%08x type=(%2x %2x)  %s\n", i, file_offset, file_length, content_type, file_type, content_name);
		if(file_type==0x04 || file_length==0){
			// is DIR
			continue;
		}

		// encrypt data
		aes_ctr_encrypt(pkg_buf+base+file_offset, file_length, file_offset, file_key, pkg_aeskey);
	}

	// make sha1 hash
	pkg_buf[4] = 0x80;
	pkg_buf[7] = 0x02;
	memset(pkg_buf+base+data_size, 0, 0x60);
	SHA1(pkg_buf, pkg_size-0x20, pkg_buf+pkg_size-0x20);

	// write back
	fp = fopen(new_name, "wb");
	fwrite(pkg_buf, pkg_size, 1, fp);
	fclose(fp);

	free(file_table);
	free(pkg_buf);
	return 0;
}

/*************************************************************/

int main(int argc, char *argv[])
{
	return fixup_pkg(argv[1], argv[2]);
}

