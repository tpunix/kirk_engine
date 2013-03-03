/*
 *  dnas.c  -- Reverse engineering of iofilemgr_dnas.prx
 *               written by tpu.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "kirk_engine.h"
#include "crypto.h"
#include "amctrl.h"
#include "utils.h"

/*************************************************************/

typedef struct {
	u8  vkey[16];

	int open_flag;
	int key_index;
	int drm_type;
	int mac_type;
	int cipher_type;

	int data_size;
	int align_size;
	int block_size;
	int block_nr;
	int data_offset;
	int table_offset;

	u8 *buf;
}PGD_DESC;

/*
typedef struct {
	PGD_DESC pgdesc;
	u32 key_index;   // 0x30
	u8  pgd_key[16]; // 0x34
	u32 flag;        // 0x44
	u32 flag_open;   // 0x48
	u32 pgd_offset;  // 0x4C
	int seek_offset; // 0x50
	u32 data_offset; // 0x54
	u32 table_offset;// 0x58
	u32 unk_5c;
	u32 unk_60;
}PspIoHookParam;
*/

u8 dnas_key1A90[] = {0xED,0xE2,0x5D,0x2D,0xBB,0xF8,0x12,0xE5,0x3C,0x5C,0x59,0x32,0xFA,0xE3,0xE2,0x43};
u8 dnas_key1AA0[] = {0x27,0x74,0xFB,0xEB,0xA4,0xA0,   1,0xD7,   2,0x56,0x9E,0x33,0x8C,0x19,0x57,0x83};

extern int verbose;

PGD_DESC *pgd_open(u8 *pgd_buf, int pgd_flag, u8 *pgd_vkey)
{
	PGD_DESC *pgd;
	MAC_KEY mkey;
	CIPHER_KEY ckey;
	u8 *fkey;
	int retv;

	printf("open PGD ...\n");

	pgd = (PGD_DESC*)malloc(sizeof(PGD_DESC));
	memset(pgd, 0, sizeof(PGD_DESC));

	pgd->buf = pgd_buf;
	pgd->key_index = *(u32*)(pgd_buf+4);
	pgd->drm_type  = *(u32*)(pgd_buf+8);

	if(pgd->drm_type==1){
		pgd->mac_type = 1;
		pgd_flag |= 4;
		if(pgd->key_index>1){
			pgd->mac_type = 3;
			pgd_flag |= 8;
		}
		pgd->cipher_type = 1;
	}else{
		pgd->mac_type = 2;
		pgd->cipher_type = 2;
	}
	pgd->open_flag = pgd_flag;

	// select fixed key
	fkey = NULL;
	if(pgd_flag&2)
		fkey = dnas_key1A90;
	if(pgd_flag&1)
		fkey = dnas_key1AA0;
	if(fkey==NULL){
		printf("pgd_open: invalid pgd_flag! %08x\n", pgd_flag);
		free(pgd);
		return NULL;
	}

	// MAC_0x80 check
	sceDrmBBMacInit(&mkey, pgd->mac_type);
	sceDrmBBMacUpdate(&mkey, pgd_buf+0x00, 0x80);
	retv = sceDrmBBMacFinal2(&mkey, pgd_buf+0x80, fkey);
	if(retv){
		printf("pgd_open: MAC_80 check failed!: %08x(%d)\n", retv, retv);
		free(pgd);
		return NULL;
	}else{
		if(verbose) printf("pgd_open: MAC_80 check pass.\n");
	}

	// MAC_0x70
	sceDrmBBMacInit(&mkey, pgd->mac_type);
	sceDrmBBMacUpdate(&mkey, pgd_buf+0x00, 0x70);
	if(pgd_vkey){
		// use given vkey
		retv = sceDrmBBMacFinal2(&mkey, pgd_buf+0x70, pgd_vkey);
		if(retv){
			printf("pgd_open: MAC_70 check failed!: %08x(%d)\n", retv, retv);
			free(pgd);
			return NULL;
		}else{
			if(verbose) printf("pgd_open: MAC_70 check pass.\n");
			memcpy(pgd->vkey, pgd_vkey, 16);
		}
	}else{
		// get vkey from MAC_70
		bbmac_getkey(&mkey, pgd_buf+0x70, pgd->vkey);
		if(verbose) hex_dump("pgd_open: get version_key from MAC_70", pgd->vkey, 16);
	}

	// decrypt PGD_DESC
	sceDrmBBCipherInit(&ckey, pgd->cipher_type, 2, pgd_buf+0x10, pgd->vkey, 0);
	sceDrmBBCipherUpdate(&ckey, pgd_buf+0x30, 0x30);
	sceDrmBBCipherFinal(&ckey);
	//hex_dump("PGD header", pgd_buf, 0x90);

	pgd->data_size   = *(u32*)(pgd_buf+0x44);
	pgd->block_size  = *(u32*)(pgd_buf+0x48);
	pgd->data_offset = *(u32*)(pgd_buf+0x4c);

	pgd->align_size = (pgd->data_size+15)&~15;
	pgd->table_offset = pgd->data_offset+pgd->align_size;
	pgd->block_nr = (pgd->align_size+pgd->block_size-1)&~(pgd->block_size-1);
	pgd->block_nr = pgd->block_nr/pgd->block_size;

	return pgd;
}

int pgd_decrypt(u8 *pgd_buf, int pgd_size, int pgd_flag, u8 *pgd_vkey)
{
	PGD_DESC *pgd;
	MAC_KEY mkey;
	CIPHER_KEY ckey;
	int retv;


	pgd = pgd_open(pgd_buf, pgd_flag, pgd_vkey);
	if(pgd==NULL){
		printf("open PGD header failed!\n");
		return -1;
	}


	printf("decrypt PGD ...\n");
	if(verbose) printf("pgd_decrypt: data_size=%08x block_size=%08x table_size=%08x data_offset=%08x\n",
			pgd->data_size, pgd->block_size, pgd->block_nr*16, pgd->data_offset);

	if(pgd->align_size+pgd->block_nr*16>pgd_size){
		printf("pgd_decrypt: invalid pgd data!\n");
		return -3;
	}


	// table MAC check
	sceDrmBBMacInit(&mkey, pgd->mac_type);
	sceDrmBBMacUpdate(&mkey, pgd_buf+pgd->table_offset, pgd->block_nr*16);
	retv = sceDrmBBMacFinal2(&mkey, pgd_buf+0x60, pgd->vkey);
	if(retv){
		printf("pgd_decrypt: MAC_table check failed!: %08x(%d)\n", retv, retv);
		return -4;
	}else{
		if(verbose) printf("pgd_decrypt: MAC_table check pass.\n");
	}

	// decrypt data
	sceDrmBBCipherInit(&ckey, pgd->cipher_type, 2, pgd_buf+0x30, pgd->vkey, 0);
	sceDrmBBCipherUpdate(&ckey, pgd_buf+0x90, pgd->align_size);
	sceDrmBBCipherFinal(&ckey);
	//hex_dump("PGD data", pgd_buf+0x90, (pgd->data_size>0x100)? 0x100 : pgd->data_size);

	return pgd->data_size;
}

int pgd_encrypt(u8 *pgd_buf, int pgd_flag, u8 *vkey)
{
	MAC_KEY mkey;
	CIPHER_KEY ckey;
	u8 *fkey;
	int i, key_index, mac_type, cipher_type, drm_type;
	int data_size, block_size, data_offset, table_offset, block_nr;

	printf("encrypt PGD ...\n");

	key_index   = 1;
	drm_type    = 1;
	mac_type    = 1;
	cipher_type = 1;

	*(u32*)(pgd_buf+4) = key_index;
	*(u32*)(pgd_buf+8) = drm_type;

	// select fixed key
	fkey = NULL;
	if(pgd_flag&2)
		fkey = dnas_key1A90;
	if(pgd_flag&1)
		fkey = dnas_key1AA0;
	if(fkey==NULL){
		printf("pgd_encrypt: invalid pgd_flag! %08x\n", pgd_flag);
		return -1;
	}

	data_size   = *(u32*)(pgd_buf+0x44);
	block_size  = *(u32*)(pgd_buf+0x48);
	data_offset = *(u32*)(pgd_buf+0x4c);

	data_size = (data_size+15)&~15;
	table_offset = data_offset+data_size;
	block_nr = (data_size+block_size-1)&~(block_size-1);
	block_nr = block_nr/block_size;

	// 1. encrypt data
	// use orig header_key
	sceDrmBBCipherInit(&ckey, cipher_type, 2, pgd_buf+0x30, vkey, 0);
	sceDrmBBCipherUpdate(&ckey, pgd_buf+data_offset, data_size);
	sceDrmBBCipherFinal(&ckey);

	// 2. build data MAC
	for(i=0; i<block_nr; i++){
		int rsize = data_size-i*block_size;
		if(rsize>block_size)
			rsize = block_size;

		sceDrmBBMacInit(&mkey, mac_type);
		sceDrmBBMacUpdate(&mkey, pgd_buf+data_offset+i*block_size, rsize);
		sceDrmBBMacFinal(&mkey, pgd_buf+table_offset+i*16, vkey);
	}

	// 3. build table MAC
	sceDrmBBMacInit(&mkey, mac_type);
	sceDrmBBMacUpdate(&mkey, pgd_buf+table_offset, block_nr*16);
	sceDrmBBMacFinal(&mkey, pgd_buf+0x60, vkey);


	// 4. encrypt PGD_DESC
	sceDrmBBCipherInit(&ckey, cipher_type, 2, pgd_buf+0x10, vkey, 0);
	sceDrmBBCipherUpdate(&ckey, pgd_buf+0x30, 0x30);
	sceDrmBBCipherFinal(&ckey);

	// 5. build MAC_0x70
	sceDrmBBMacInit(&mkey, mac_type);
	sceDrmBBMacUpdate(&mkey, pgd_buf+0x00, 0x70);
	sceDrmBBMacFinal(&mkey, pgd_buf+0x70, vkey);


	// 6. build MAC_0x80
	sceDrmBBMacInit(&mkey, mac_type);
	sceDrmBBMacUpdate(&mkey, pgd_buf+0x00, 0x80);
	sceDrmBBMacFinal(&mkey, pgd_buf+0x80, fkey);

	return 0;
}


