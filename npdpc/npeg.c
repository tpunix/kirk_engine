

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "utils.h"

#include "kirk_engine.h"
#include "amctrl.h"

/*****************************************************************************/

int write_file(char *file, void *buf, int size);
int cccLZRDecompress(void *out, unsigned int out_capacity, void *in, void *in_end);
int lzrc_decompress(void *out, int out_len, void *in, int in_len);
int lzrc_compress(void *out, int out_len, void *in, int in_len);

/*****************************************************************************/

u8 header_key[16];
FILE *iso_fd;
int offset_psar;
u8 *np_table;
int total_blocks;
int block_size;
u8 version_key[16];

/*****************************************************************************/

int NpegOpen(char *name, u8 *header, u8 *table, int *table_size)
{
	MAC_KEY mkey;
	CIPHER_KEY ckey;
	u8 pbp_buf[0x28];
	u8 *np_header;
	int start, end, lba_size, offset_table;
	u32 *tp;
	int retv, i;

	np_header  = header;
	np_table   = table;

	iso_fd = fopen(name, "rb");
	if(iso_fd==NULL)
		return -2;

	// read PBP header
	retv = fread(pbp_buf, 0x28, 1, iso_fd);
	if(retv!=1)
		return -3;

	// check "PBP"
	if(*(u32*)pbp_buf!=0x50425000)
		return -4;

	offset_psar = *(u32*)(pbp_buf+0x24);
	fseek(iso_fd, offset_psar, SEEK_SET);

	retv = fread(np_header, 0x0100, 1, iso_fd);
	if(retv!=1)
		return -6;

	// check "NPUMDIMG"
	if(strncmp((char*)np_header, "NPUMDIMG", 8)){
		printf("DATA.PSAR isn't a NPUMDIMG!\n");
		return -7;
	}

	// bbmac_getkey
	sceDrmBBMacInit(&mkey, 3);
	sceDrmBBMacUpdate(&mkey, np_header, 0xc0);
	bbmac_getkey(&mkey, np_header+0xc0, version_key);

	// header MAC check
	sceDrmBBMacInit(&mkey, 3);
	sceDrmBBMacUpdate(&mkey, np_header, 0xc0);
	retv = sceDrmBBMacFinal2(&mkey, np_header+0xc0, version_key);
	if(retv){
		printf("NP header MAC check failed!\n");
		return -13;
	}

	write_file("version_key.bin", version_key, 16);

	// decrypt NP header
	memcpy(header_key, np_header+0xa0, 0x10);
	sceDrmBBCipherInit(&ckey, 1, 2, header_key, version_key, 0);
	sceDrmBBCipherUpdate(&ckey, np_header+0x40, 0x60);
	sceDrmBBCipherFinal(&ckey);

	start = *(u32*)(np_header+0x54); // LBA start
	end   = *(u32*)(np_header+0x64); // LBA end
	block_size = *(u32*)(np_header+0x0c); // block_size
	lba_size = (end-start+1); // LBA size of ISO
	total_blocks = (lba_size+block_size-1)/block_size; // total blocks;

	offset_table = *(u32*)(np_header+0x6c); // table offset
	fseek(iso_fd, offset_psar+offset_table, SEEK_SET);

	*table_size = total_blocks*32;
	retv = fread(np_table, *table_size, 1, iso_fd);
	if(retv!=1)
		return -18;

	// table mac test
	int msize;
	u8 bbmac[16];

	sceDrmBBMacInit(&mkey, 3);
	for(i=0; i<*table_size; i+=0x8000){
		if(i+0x8000>*table_size)
			msize = *table_size-i;
		else
			msize = 0x8000;
		sceDrmBBMacUpdate(&mkey, np_table+i, msize);
	}
	sceDrmBBMacFinal(&mkey, bbmac, version_key);
	bbmac_build_final2(3, bbmac);

	tp = (u32*)np_table;
	for(i=0; i<total_blocks; i++){
		u32 a0, a1, a2, a3, v0, v1, t0, t1, t2;

		v1 = tp[0];
		v0 = tp[1];
		a0 = tp[2];
		t1 = tp[3];

		a1 = tp[4];
		a2 = tp[5];
		a3 = tp[6];
		t0 = tp[7];

		t2 = v1^v0;
		v0 = v0^a0;
		v1 = v1^t1;
		a0 = a0^t1;

		a1 = a1^a0;
		a2 = a2^v0;
		a3 = a3^v1;
		t0 = t0^t2;

		tp[4] = a1;
		tp[5] = a2;
		tp[6] = a3;
		tp[7] = t0;

		tp += 8;
	}

	return 0;
}

/*****************************************************************************/

int NpegReadBlock(u8 *data_buf, u8 *out_buf, int block)
{
	MAC_KEY mkey;
	CIPHER_KEY ckey;
	int retv;
	u32 *tp;

	tp = (u32*)(np_table+block*32);
	if(tp[7]!=0){
		if(block==(total_blocks-1))
			return 0x00008000;
		else
			return -1;
	}

	retv = fseek(iso_fd, offset_psar+tp[4], SEEK_SET);
	if(retv<0){
		if(block==(total_blocks-1))
			return 0x00008000;
		else
			return -1;
	}

	retv = fread(data_buf, tp[5], 1, iso_fd);
	if(retv!=1){
		if(block==(total_blocks-1))
			return 0x00008000;
		else
			return -2;
	}

	if((tp[6]&1)==0){
		sceDrmBBMacInit(&mkey, 3);
		sceDrmBBMacUpdate(&mkey, data_buf, tp[5]);
		retv = sceDrmBBMacFinal2(&mkey, (u8*)tp, version_key);
		if(retv<0){
			if(block==(total_blocks-1))
				return 0x00008000;
			else
				return -5;
		}
	}

	if((tp[6]&4)==0){
		sceDrmBBCipherInit(&ckey, 1, 2, header_key, version_key, tp[4]>>4);
		sceDrmBBCipherUpdate(&ckey, data_buf, tp[5]);
		sceDrmBBCipherFinal(&ckey);
	}

	if(tp[5]<block_size*2048){
#if 0
		char name[32];
		//printf("block %4d: %08x\n", block, tp[5]);
		sprintf(name, "cdata/%4d.bin", block);
		write_file(name, data_buf, tp[5]);
		retv = 0x00008000;
#endif

#if 0
		retv = cccLZRDecompress(out_buf, 0x00100000, data_buf, 0);
#else
		retv = lzrc_decompress(out_buf, 0x00100000, data_buf, tp[5]);
#endif
		if(retv!=block_size*2048){
			printf("LZR decompress error! retv=%d\n", retv);
		}
#if 0
// compress test
{
	u8 *dbuf, *ebuf;
	int esize, dsize;
	char name[32];

	ebuf = malloc(1024*1024);
	dbuf = malloc(1024*1024);
	memset(ebuf, 0, 1024*1024);
	memset(dbuf, 0, 1024*1024);

	esize = lzrc_compress(ebuf, 1024*1024, out_buf, retv);
	dsize = lzrc_decompress(dbuf, 1024*1024, ebuf, esize);
	if(dsize!=retv || memcmp(out_buf, dbuf, dsize)){
		printf("lzrc_compress failed on block %d!\n", block);
		sprintf(name, "lzrc_%4d.bin", block);
		write_file(name, data_buf, tp[5]);
	}

	free(ebuf);
	free(dbuf);
}
#endif

	}else{
		memcpy(out_buf, data_buf, tp[5]);
		retv = 0x00008000;
	}

	return retv;
}

/*****************************************************************************/

int NpegClose(void)
{
	fclose(iso_fd);
	iso_fd = NULL;
	return 0;
}

/*****************************************************************************/

