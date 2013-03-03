/*
 *  fake_np.c  -- make a fake NPdemo package
 *                written by tpu.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "utils.h"

#include "kirk_engine.h"
#include "amctrl.h"
#include "fixed.h"

#include "isoreader.h"

/*************************************************************/

static u8 zero_lz[0x50] = {
	0x05, 0xff, 0x80, 0x01, 0x0e, 0xd6, 0xe7, 0x37, 0x04, 0x3f, 0x53, 0x0b, 0xbc, 0xe7, 0xa3, 0x72, 
	0x14, 0xdc, 0x38, 0x8e, 0x0c, 0xaa, 0x94, 0x93, 0x46, 0xbf, 0xf8, 0x72, 0x15, 0x04, 0x7e, 0x9c, 
	0xe0, 0xec, 0x8b, 0x6c, 0x7d, 0xee, 0xf0, 0x7a, 0x90, 0x91, 0x0e, 0xb3, 0xc7, 0x8b, 0xd8, 0x08, 
	0x9d, 0x68, 0x09, 0xe5, 0x9e, 0xfe, 0x43, 0x03, 0x5b, 0x0b, 0x7c, 0x52, 0xe4, 0xfe, 0xfe, 0x66, 
	0x26, 0xe5, 0xcc, 0x83, 0xfc, 0x55, 0x16, 0xd2, 0x5e, 0x92, 0x00, 0x00, 0x8a, 0xed, 0x5e, 0x1a, 
};

/*************************************************************/

FILE *open_file(char *name, int *size)
{
	FILE *fp;

	fp = fopen(name, "rb");
	if(fp==NULL){
		//printf("Open file %s failed!\n", name);
		return NULL;
	}

	fseek(fp, 0, SEEK_END);
	*size = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	return fp;
}

u8 *load_file_from_ISO(const char *iso, char *name, int *size)
{
	int ret;
	u32 lba;
	u8 *buf;

	ret = isoOpen(iso);
	if (ret < 0) {
		return NULL;
	}

	ret = isoGetFileInfo(name, (u32*)size, &lba);
	if (ret < 0) {
		isoClose();
		return NULL;
	}

	buf = malloc(*size);
	if (buf == NULL) {
		isoClose();
		return NULL;
	}

	ret = isoRead(buf, lba, 0, *size);
	if (ret < 0) {
		isoClose();
		return NULL;
	}

	isoClose();
	return buf;
}

int write_file(char *file, void *buf, int size)
{
	FILE *fp;
	int written;

	fp = fopen(file, "wb");
	if(fp==NULL)
		return -1;
	written = fwrite(buf, 1, size, fp);
	fclose(fp);

	return written;
}

int main(int argc, char *argv[])
{
	MAC_KEY mkey;
	CIPHER_KEY ckey;
	FILE *fp;
	u8 fixed_key[16], tmp_header[256];
	u8 *np_buf, *pbp_header, *tb;
	u8 *ico0_buf, *ico1_buf, *pic0_buf, *pic1_buf, *snd0_buf;
	int i, block_size, iso_block, offset, header_size;
	int ico0_size, ico1_size, pic0_size, pic1_size, snd0_size, iso_size, np_size;
	int start, end, lba_size, total_block;

	ico0_size = 0;
	ico1_size = 0;
	pic0_size = 0;
	pic1_size = 0;
	snd0_size = 0;
	iso_size = 0;

	printf("fake_np v0.5 by tpu\n\n");

	kirk_init();
	// test Cipher
	memcpy(tmp_header, np_header, sizeof(tmp_header));

	sceNpDrmGetFixedKey(fixed_key, (char*)np_header+0x10, *(int*)(np_header+0x08));
	sceDrmBBCipherInit(&ckey, 1, 2, np_header+0xa0, fixed_key, 0);
	sceDrmBBCipherUpdate(&ckey, tmp_header+0x40, 0x60);
	sceDrmBBCipherFinal(&ckey);

	block_size = *(u32*)(np_header+0x0c);
	start = *(u32*)(tmp_header+0x54);
	end   = *(u32*)(tmp_header+0x64);
	lba_size = end-start+1;
	total_block = (lba_size+block_size-1)/block_size;

	// build NPUMDIMG
	fp = open_file("np.iso", &iso_size);

	if(fp==NULL){
		printf("Open np.iso faield!\n");
		return -1;
	}

	block_size *= 2048;

	if(iso_size>(total_block-1)*block_size){
		printf("ISO file too big! %d>%d\n", iso_size, (total_block-1)*block_size);
		fclose(fp);
		return -1;
	}

	printf("Load np.iso ...\n");

	np_size = 0x0100+total_block*(block_size+0x20);
	np_buf = malloc(np_size);

	if (np_buf == NULL) {
		printf("np_buf: cannot allocate %d bytes\n", np_size);
		fclose(fp);
		return -2;
	}

	memset(np_buf, 0, np_size);

	iso_block = iso_size/block_size;
	offset = 0x0100+total_block*0x20;

	fread(np_buf+offset, iso_size, 1, fp);
	fclose(fp);

	memcpy(np_buf, np_header, 0x0100);

	// build lookup table
	for(i=0; i<iso_block; i++){
		tb = np_buf+0x100+i*32;
		memset(tb, 0, 32);
		*(u32*)(tb+0x10) = offset;
		*(u32*)(tb+0x14) = block_size;
		*(u32*)(tb+0x18) = 0x00000005;
		offset += block_size;
	}

	// fill remain table entry with zero data
	for(i=iso_block; i<total_block; i++){
		tb = np_buf+0x100+i*32;
		memset(tb, 0, 32);
		*(u32*)(tb+0x10) = offset;
		*(u32*)(tb+0x14) = 0x50;
		*(u32*)(tb+0x18) = 0x00000005;
		memcpy(np_buf+offset, zero_lz, 0x50);
		offset += 0x50;
	}

	np_size = offset;

	// crack the table hash
	sceNpDrmGetFixedKey(fixed_key, (char*)np_buf+0x10, *(int*)(np_buf+0x08));
	sceDrmBBMacInit(&mkey, 3);
	sceDrmBBMacUpdate(&mkey, np_buf+0x100, total_block*0x20);
	bbmac_forge(&mkey, np_buf+0xb0, fixed_key, np_buf+0x100+total_block*0x20-0x10);

	// load others
	ico0_buf = load_file_from_ISO("np.iso", "/PSP_GAME/ICON0.PNG", &ico0_size);
	ico1_buf = load_file_from_ISO("np.iso", "/PSP_GAME/ICON1.PMF", &ico1_size);
	pic0_buf = load_file_from_ISO("np.iso", "/PSP_GAME/PIC0.PNG",  &pic0_size);
	pic1_buf = load_file_from_ISO("np.iso", "/PSP_GAME/PIC1.PNG",  &pic1_size);
	snd0_buf = load_file_from_ISO("np.iso", "/PSP_GAME/SND0.AT3",  &snd0_size);

	header_size = ico0_size+ico1_size+pic0_size+pic1_size+snd0_size;
	header_size += param_sfo_size;
	header_size += data_psp_size;
	pbp_header = malloc(header_size+4096);
	memset(pbp_header, 0, header_size+4096);

	*(u32*)(pbp_header+0) = 0x50425000;
	*(u32*)(pbp_header+4) = 0x00010001;

	offset = 0x28;

	// param.sfo
	printf("load PARAM.SFO ...\n");
	*(u32*)(pbp_header+0x08) = offset;
	memcpy(pbp_header+offset, param_sfo, param_sfo_size);
	offset += param_sfo_size;

	// icon0.png
	if(ico0_size)
		printf("load ICON0.PNG ...\n");
	*(u32*)(pbp_header+0x0c) = offset;
	memcpy(pbp_header+offset, ico0_buf, ico0_size);
	offset += ico0_size;
	offset = (offset+15)&~15;

	// icon1.pmf
	if(ico1_size)
		printf("load ICON1.PMF ...\n");
	*(u32*)(pbp_header+0x10) = offset;
	memcpy(pbp_header+offset, ico1_buf, ico1_size);
	offset += ico1_size;
	offset = (offset+15)&~15;

	// pic0.png
	if(pic0_size)
		printf("load PIC0.PNG ...\n");
	*(u32*)(pbp_header+0x14) = offset;
	memcpy(pbp_header+offset, pic0_buf, pic0_size);
	offset += pic0_size;
	offset = (offset+15)&~15;

	// pic1.png
	if(pic1_size)
		printf("load PIC1.PNG ...\n");
	*(u32*)(pbp_header+0x18) = offset;
	memcpy(pbp_header+offset, pic1_buf, pic1_size);
	offset += pic1_size;
	offset = (offset+15)&~15;

	// snd0.at3
	if(snd0_size)
		printf("load SND0.AT3 ...\n");
	*(u32*)(pbp_header+0x1c) = offset;
	memcpy(pbp_header+offset, snd0_buf, snd0_size);
	offset += snd0_size;
	offset = (offset+15)&~15;

	// data.psp
	printf("load DATA.PSP ...\n");
	*(u32*)(pbp_header+0x20) = offset;
	memcpy(pbp_header+offset, data_psp, data_psp_size);
	offset += data_psp_size;
	offset = (offset+15)&~15;

	// data.psar
	*(u32*)(pbp_header+0x24) = offset;

	// write all
	printf("Write EBOOT.PBP ...\n");
	fp = fopen("EBOOT.PBP", "wb");
	if(fp==NULL){
		printf("    Write failed!\n");
		return -1;
	}
	fwrite(pbp_header, offset, 1, fp);
	fwrite(np_buf, np_size, 1, fp);
	fclose(fp);

	return 0;
}
