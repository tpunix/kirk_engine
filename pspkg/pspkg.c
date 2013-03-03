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

#include "utils.h"
#include "kirk_engine.h"
#include "crypto.h"

typedef unsigned long long u64;

int do_list;
int do_extract;
int do_decrypt;
int do_encrypt;
int do_check;

u8 header[4096];

/*************************************************************/

typedef struct {
	u32 magic;
	u8  debug;
	u8  zero_5[2];
	u8  type;
	u32 meta_offset;
	u32 unk_0c;

	u32 header_size;
	u32 item_count;
	u64 package_size;

	u64 data_offset;
	u64 data_size;
	char content_id[0x30];
	u8 QA_digest[0x10];
	u8 K_license[0x10];
}PKG_HEADER;


typedef struct {
	u32 unk_00;
	u32 unk_04;
	u32 drm_type;
	u32 unk_0c;

	u32 unk_10;
	u32 content_type;
	u32 unk_18;
	u32 unk_1c;

	u32 package_type;
	u32 unk_24;
	u32 unk_28;
	u16 second_ver;
	u16 unk_2e;

	u32 data_size;
	u32 unk_34;
	u32 unk_38;
	u16 packaged_by;
	u8  package_ver_h;
	u8  package_ver_l;

	u32 unk_40;
	u32 unk_44;
	char title_id[12];
	u32 unk_54;
	u32 unk_58;
	u32 unk_5c;

	u32 unk_60;
	u8  qa_digest[16];
	u32 unk_74;
	u32 unk_78;
	u16 unk_7c;
	u16 unk_7e;

	u32 unk_80;
	u32 unk_84;
	u32 unk_88;
	u32 unk_8c;

	u8  unk_90[16];
}META_INFO;


/*************************************************************/

void mkdir_p(char *dname)
{
	char name[256];
	char *p, *cp;

	strcpy(name, dname);

	cp = name;
	while(1){
		p = strchr(cp, '/');
		if(p==NULL)
			p = strchr(cp, '\\');
		if(p==NULL)
			break;

		*p = 0;
		//mkdir(name, 0777); // for *nix
		mkdir(name); // for mingw
		*p = '/';
		cp = p+1;
	};
}

/*************************************************************/

u8 psp_pkg_key[16] = {0x07,0xF2,0xC6,0x82,0x90,0xB5,0x0D,0x2C,0x33,0x81,0x8D,0x70,0x9B,0x60,0xE6,0x2B};
u8 ps3_pkg_key[16] = {0x2E,0x7B,0x71,0xD7,0xC9,0xC9,0xA1,0x4E,0xA3,0x22,0x1F,0x18,0x88,0x28,0xB8,0xF8};


u32 get_be32(u8 *buf)
{
	return (u32)( (buf[0]<<24) | (buf[1]<<16) | (buf[2]<<8) | buf[3]);
}

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

void show_pkg_info(u8 *pbuf)
{
	PKG_HEADER *ph;
	META_INFO *mh;
	int i;

	ph = (PKG_HEADER*)pbuf;
	mh = (META_INFO*)(pbuf+get_be32((u8*)&ph->meta_offset));

	printf("ContentID        = %s\n", ph->content_id);

	printf("DRMType          = ");
	if(mh->drm_type==0x01000000)
		printf("Network\n");
	else if(mh->drm_type==0x02000000)
		printf("Local\n");
	else if(mh->drm_type==0x03000000)
		printf("Free\n");
	else
		printf("Unknow\n");

	printf("ContentType      = ");
	if(ph->debug!=0x80)
		printf("Debug\n");
	else if(ph->type==2)
		printf("PSP\n");
	else if(ph->type==3)
		printf("PS3\n");
	else
		printf("Unknow\n");

	printf("TitleID          = %s\n", mh->title_id);
	printf("PackageVersion   = %02x.%02x\n", mh->package_ver_h, mh->package_ver_l);


	printf("# QA_Digest      : 0x");
	for(i=0; i<16; i++){
		printf("%02X", mh->qa_digest[i]);
	}
	printf("\n");

}

/*************************************************************/

int extract_pkg(char *pkg_name)
{
	FILE *fp, *out_fp;
	u8 file_key[0x20], sha1_key[0x40];
	u8 *pkg_aeskey, *file_table, *block_buf;
	int i, base, total_file, is_debug;
	char dir_name[64], out_name[64], *p;

	fp = fopen(pkg_name, "rb");

	fread(header, 4096, 1, fp);
	if(*(u32*)(header)!=0x474b507f){
		printf("Selected file isn't a PKG file!\n");
		return -1;
	}

	strcpy(dir_name, pkg_name);
	p = strrchr(dir_name, '.');
	if(p)
		*p = '_';
	else
		dir_name[0] = '_';

	pkg_aeskey = NULL;
	memset(sha1_key, 0, 0x40);
	is_debug = 0;
	if(header[4]!=0x80){
		is_debug = 1;
	}else if(header[7]==0x02){
		pkg_aeskey = psp_pkg_key;
	}else if(header[7]==0x03){
		pkg_aeskey = ps3_pkg_key;
	}else{
		printf("Unknow PKG type: %d\n", header[7]);
		return -1;
	}

	base = get_be32(header+0x24);
	total_file = get_be32(header+0x14);

	memcpy(sha1_key+0x00, header+0x60, 8);
	memcpy(sha1_key+0x08, header+0x60, 8);
	memcpy(sha1_key+0x10, header+0x68, 8);
	memcpy(sha1_key+0x18, header+0x68, 8);
	memcpy(file_key, header+0x70, 0x10);

	show_pkg_info(header);

	if(do_list==0 && do_extract==0){
		fclose(fp);
		return 0;
	}

	// read and decrypt file table
	file_table = malloc(total_file*0x20);
	fseek(fp, base, SEEK_SET);
	fread(file_table, 0x20, total_file, fp);
	if(is_debug)
		sha1_ctr_encrypt(file_table, total_file*0x20, 0, sha1_key);
	else
		aes_ctr_encrypt(file_table, total_file*0x20, 0, file_key, pkg_aeskey);

	block_buf = malloc(64*1024);
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
		int read_length;

		// read encrypted name
		fseek(fp, base+name_offset, SEEK_SET);
		fread(content_name, name_length, 1, fp);
		if(is_debug){
			sha1_ctr_encrypt(content_name, name_length, name_offset, sha1_key);
		}else{
			if(content_type==0x90){
				pkg_aeskey = psp_pkg_key;
			}else{
				pkg_aeskey = ps3_pkg_key;
			}
			aes_ctr_encrypt(content_name, name_length, name_offset, file_key, pkg_aeskey);
		}
		content_name[name_length] = 0;
		sprintf(out_name, "%s/%s", dir_name, content_name);

		printf("file %2d: offset=%08x length=%08x type=(%2x %2x)  %s\n", i, file_offset, file_length, content_type, file_type, out_name);
		if(file_type==0x04 || file_length==0){
			// is DIR
			continue;
		}

		if(do_extract==1){
			mkdir_p(out_name);

			// read encrypted data
			out_fp = fopen(out_name, "wb");

			fseek(fp, base+file_offset, SEEK_SET);
			while(file_length>0){
				read_length = 64*1024;
				if(file_length<read_length)
					read_length = file_length;

				fread(block_buf, read_length, 1, fp);
				if(is_debug)
					sha1_ctr_encrypt(block_buf, read_length, file_offset, pkg_aeskey);
				else
					aes_ctr_encrypt(block_buf, read_length, file_offset, file_key, pkg_aeskey);
				fwrite(block_buf, read_length, 1, out_fp);
				file_length -= read_length;
				file_offset += read_length;
			}
			fclose(out_fp);
		}

	}

	fclose(fp);
	free(file_table);
	free(block_buf);

	return 0;
}

/*************************************************************/


int fixup_pkg(char *pkg_name, char *pkg_type, char *new_name)
{
	FILE *fp;
	u8 file_key[16], sha1_key[0x40];
	u8 *pkg_buf, *pkg_aeskey, *file_table;
	int i, base, data_size, pkg_size, total_file;
	int is_debug;

	fp = fopen(pkg_name, "rb");

	/* header check */
	fread(header, 4096, 1, fp);
	if(*(u32*)(header)!=0x474b507f){
		printf("Selected file isn't a PKG file!\n");
		return -1;
	}

	memcpy(file_key, header+0x70, 0x10);
	pkg_aeskey = psp_pkg_key;

	/* read all file */
	fseek(fp, 0, SEEK_END);
	pkg_size = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	pkg_buf = malloc(pkg_size);
	fread(pkg_buf, pkg_size, 1, fp);
	fclose(fp);

	show_pkg_info(header);

	if(do_check==1){
		u8 sha1_result[32];
		SHA1(pkg_buf, pkg_size-0x20, sha1_result);
		if(memcmp(sha1_result, pkg_buf+pkg_size-0x20, 0x14)){
			printf("package check failed!\n");
			hex_dump("calculate SHA1:", sha1_result, 0x14);
			hex_dump("package   SHA1:", pkg_buf+pkg_size-0x20, 0x14);
		}else{
			printf("package check OK!\n");
		}

		free(pkg_buf);
		return 0;
	}


	/* make sha1 key */
	memset(sha1_key, 0, 0x40);
	memcpy(sha1_key+0x00, pkg_buf+0x60, 8);
	memcpy(sha1_key+0x08, pkg_buf+0x60, 8);
	memcpy(sha1_key+0x10, pkg_buf+0x68, 8);
	memcpy(sha1_key+0x18, pkg_buf+0x68, 8);

	base = get_be32(pkg_buf+0x24);
	data_size = get_be32(pkg_buf+0x2c);
	total_file = get_be32(pkg_buf+0x14);


	if(header[4]==0xFF)
		goto _skip_decrypt;

	// decrypt pkg
	if(header[4]==!0x80){
		sha1_ctr_encrypt(pkg_buf+base, data_size, 0, sha1_key);
	}else{
		printf(" -d only support debug package!\n");
		free(pkg_buf);
		return 0;
	}
	pkg_buf[4] = 0xff;

_skip_decrypt:
	if(do_encrypt==0)
		goto _save_file;

	is_debug = 0;
	if(strcmp(pkg_type, "debug")==0){
		is_debug = 1;
		pkg_buf[4] = 0x00;
		pkg_buf[7] = 0x01;
	}else if(strcmp(pkg_type, "psp")==0){
		pkg_aeskey = psp_pkg_key;
		pkg_buf[4] = 0x80;
		pkg_buf[7] = 0x02;
	}else if(strcmp(pkg_type, "ps3")==0){
		pkg_aeskey = ps3_pkg_key;
		pkg_buf[4] = 0x80;
		pkg_buf[7] = 0x03;
	}else{
		printf("Unknow encrypt type: %s\n", pkg_type);
	}

	// read file table
	file_table = malloc(total_file*0x20);
	memcpy(file_table, pkg_buf+base, total_file*0x20);

	// encrypt file table
	if(is_debug)
		sha1_ctr_encrypt(pkg_buf+base, total_file*0x20, 0, sha1_key);
	else
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
		if(is_debug){
			sha1_ctr_encrypt(pkg_buf+base+name_offset, name_length, name_offset, sha1_key);
		}else{
			if(content_type==0x90){
				pkg_aeskey = psp_pkg_key;
			}else{
				pkg_aeskey = ps3_pkg_key;
			}
			aes_ctr_encrypt(pkg_buf+base+name_offset, name_length, name_offset, file_key, pkg_aeskey);
		}

		printf("file %2d: offset=%08x length=%08x type=(%2x %2x)  %s\n", i, file_offset, file_length, content_type, file_type, content_name);
		if(file_type==0x04 || file_length==0){
			// is DIR
			continue;
		}

		// encrypt data
		if(is_debug)
			sha1_ctr_encrypt(pkg_buf+base+file_offset, file_length, file_offset, sha1_key);
		else
			aes_ctr_encrypt(pkg_buf+base+file_offset, file_length, file_offset, file_key, pkg_aeskey);
	}
	free(file_table);

	// make sha1 hash
	SHA1(pkg_buf, pkg_size-0x20, pkg_buf+pkg_size-0x20);

_save_file:
	// write back
	fp = fopen(new_name, "wb");
	fwrite(pkg_buf, pkg_size, 1, fp);
	fclose(fp);

	free(pkg_buf);
	return 0;
}



/*************************************************************/

int main(int argc, char *argv[])
{
	int ap;
	char *pkg_name, *pkg_type, *out_name;

	do_list = 0;
	do_extract = 0;
	do_decrypt = 0;
	do_encrypt = 0;
	do_check = 0;

	pkg_name = NULL;
	out_name = NULL;
	pkg_type = NULL;

	// parameter process
	ap = 1;
	while(ap<argc){
		if(argv[ap][0]=='-'){
			if(argv[ap][1]=='e'){
				if(ap+1==argc)
					goto _help;
				pkg_type = argv[ap+1];
				ap += 1;
				do_encrypt = 1;
			}else if(argv[ap][1]=='l'){
				do_list = 1;
			}else if(argv[ap][1]=='x'){
				do_extract = 1;
			}else if(argv[ap][1]=='d'){
				do_decrypt = 1;
			}else if(argv[ap][1]=='c'){
				do_check = 1;
			}else{
				printf(" unkonw param: %s\n", argv[ap]);
				goto _help;
			}
		}else{
			if(pkg_name==NULL){
				pkg_name = argv[ap];
			}else if(out_name==NULL){
				out_name = argv[ap];
			}
		}

		ap += 1;
	}

	if(pkg_name==NULL)
		goto _help;
	if(out_name==NULL)
		out_name = pkg_name;

	if(do_check==0 && do_decrypt==0 && do_encrypt==0){
		return extract_pkg(pkg_name);
	}else{
		return fixup_pkg(pkg_name, pkg_type, out_name);
	}

_help:
	printf("\n");
	printf("pspkg: PSP/PS3 packge tools v0.5, writen by tpu\n");
	printf(" usage: pspkg [-l] [-x] [-c] [-d] [-e type] <pkg_file> [new_file]\n");
	printf("    -c     : check package\n");
	printf("    -l     : list content in package\n");
	printf("    -x     : extract all content in package\n");
	printf("    -d     : decrypt debug package\n");
	printf("    -e type: encrypt debug package with type: psp/ps3/debug\n");
	printf("    \n");

	return 0;
}

