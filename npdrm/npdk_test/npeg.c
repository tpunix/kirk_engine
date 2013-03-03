

#include <pspsdk.h>
#include <pspkernel.h>
#include <pspiofilemgr.h>
#include <psploadcore.h>
#include <pspthreadman_kernel.h>

#include <stdio.h>
#include <string.h>

#include "lzdecode.h"

#define byte_swap(x) ( ((x&0xff)<<24) | ((x&0xff00)<<8) | ((x&0xff0000)>>8) | ((x&0xff000000)>>24) )


/*****************************************************************************/

int sceNpDrmGetIDps(u8 *psid);

int sceNpDrmGetFixedKey(u8 *version_key, u8 *name, u32 type);
int sceNpDrmGetVersionKey(u8 *version_key, u8 *act_buf, u8 *rif_buf, u32 type);

int sceDrmBBMacInit(u8 *mac_key, int type);
int sceDrmBBMacUpdate(u8 *mac_key, u8 *buf, int size);
int sceDrmBBMacFinal2(u8 *mac_key, u8 *buf, u8 *version_key);

int sceDrmBBCipherInit(u8 *cipher_key, int unk1, int unk2, u8 *header_key, u8 *version_key, int unk3);
int sceDrmBBCipherUpdate(u8 *cipher_key, u8 *buf, int size);
int sceDrmBBCipherFinal(u8 *cipher_key);

int (*lz_decomp)(u8 *out_buf, int out_size, u8 *src_buf, int src_size) = (void*)lzdecode;

void hex_dump(char *str, u8 *buf, int size);

/*****************************************************************************/

u8 header_key[16];
int iso_fd;
int offset_psar;
u8 *np_actdat;
u8 *np_table;
int block_size;
u8 version_key[16];

/*****************************************************************************/

int NpegOpen(char *name, u8 *header, u8 *act_dat, u8 *table, int *table_size)
{
	u8 psid[0x10];
	u8 pbp_buf[0x28];
	u8 rif_buf[0x98];
	u8 mac_key[0x30];
	u8 cipher_key[0x20];
	char rif_name[0x40];
	u8 *np_header, *act_buf;
	int start, end, lba_size, total_blocks, offset_table;
	u32 *tp;
	int retv, i, fd, type;

	np_header  = header;
	np_actdat  = act_dat;
	np_table   = table;

	retv = sceNpDrmGetIDps(psid);
	if(retv<0)
		return -1;

	iso_fd = sceIoOpen(name, 0x04000000|PSP_O_RDONLY, 0);
	if(iso_fd<0)
		return -2;

	// read PBP header
	retv = sceIoRead(iso_fd, pbp_buf, 0x28);
	if(retv<0x28)
		return -3;
	// check "PBP"
	if(*(u32*)pbp_buf!=0x50425000)
		return -4;

	offset_psar = *(u32*)(pbp_buf+0x24);
	retv = sceIoLseek(iso_fd, offset_psar, SEEK_SET);
	if(retv<0)
		return -5;

	retv = sceIoRead(iso_fd, np_header, 0x0100);
	if(retv<0x0100)
		return -6;

	// check "NPUMDIMG"
	if(*(u32*)(np_header+0)!=0x4d55504e)
		return -7;
	if(*(u32*)(np_header+4)!=0x474d4944)
		return -7;

	type = *(u32*)(np_header+8);
	if(type&0x01000000){
		retv = sceNpDrmGetFixedKey(version_key, np_header+0x10, type);
		hex_dump("fixed key:", version_key, 16);
	}else{
		memset(rif_name, 0, 0x40);
		sprintf(rif_name, "ms0:/PSP/LICENSE/%s.rif", np_header+0x10);

		fd = sceIoOpen(rif_name, 0x04000000|PSP_O_RDONLY, 0);
		retv = sceIoRead(fd, rif_buf, 0x98);
		sceIoClose(fd);

		if(retv!=0x98)
			return -8;

		type = *(u32*)(rif_buf+4);
		type = byte_swap(type);
		if(type!=3){
			fd = sceIoOpen("flash2:/act.dat", 0x04000000|PSP_O_RDONLY, 0);
			if(fd<0)
				return -9;
			retv = sceIoRead(fd, np_actdat, 0x1038);
			sceIoClose(fd);

			if(retv!=0x1038)
				return -10;
			act_buf = np_actdat;
		}else{
			act_buf = NULL;
		}

		type = *(u32*)(np_header+8);
		retv = sceNpDrmGetVersionKey(version_key, act_buf, rif_buf, type);
	}
	if(retv<0)
		return retv;

	write_file("version_key.bin", version_key, 16);

	memcpy(header_key, np_header+0xa0, 0x10);
	retv = sceDrmBBMacInit(mac_key, 3);
	if(retv<0)
		return -11;

	retv = sceDrmBBMacUpdate(mac_key, np_header, 0xc0);
	if(retv<0)
		return -12;

	retv = sceDrmBBMacFinal2(mac_key, np_header+0xc0, version_key);
	if(retv<0)
		return -13;

	retv = sceDrmBBCipherInit(cipher_key, 1, 2, header_key, version_key, 0);
	if(retv<0)
		return -14;

	retv = sceDrmBBCipherUpdate(cipher_key, np_header+0x40, 0x60);
	if(retv<0)
		return -15;

	retv = sceDrmBBCipherFinal(cipher_key);
	if(retv<0)
		return -16;


	start = *(u32*)(np_header+0x54); // LBA start
	end   = *(u32*)(np_header+0x64); // LBA end
	block_size = *(u32*)(np_header+0x0c); // block_size
	lba_size = (end-start+1); // LBA size of ISO
	total_blocks = (lba_size+block_size-1)/block_size; // total blocks;

	offset_table = *(u32*)(np_header+0x6c); // table offset
	sceIoLseek(iso_fd, offset_psar+offset_table, SEEK_SET);

	*table_size = total_blocks*32;
	retv = sceIoRead(iso_fd, np_table, *table_size);
	if(retv<*table_size)
		return -18;

	// table mac test
	int msize;
	u8 bbmac[16];

	sceDrmBBMacInit(mac_key, 3);
	for(i=0; i<*table_size; i+=0x8000){
		if(i+0x8000>*table_size)
			msize = *table_size-i;
		else
			msize = 0x8000;
		sceDrmBBMacUpdate(mac_key, np_table+i, msize);
		hex_dump("MacUpdate:", mac_key+4, 32+4);
	}
	sceDrmBBMacFinal(mac_key, bbmac, version_key);
	hex_dump("MacFinal:", bbmac, 16);

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
	u8 cipher_key[0x20];
	u8 mac_key[0x30];
	int retv;
	u32 *tp;

	tp = (u32*)(np_table+block*32);

	retv = sceIoLseek(iso_fd, offset_psar+tp[4], 0);
	if(retv<0)
		return -1;

	retv = sceIoRead(iso_fd, data_buf, tp[5]);
	if(retv!=tp[5])
		return -2;

	if((tp[6]&1)==0){
		retv = sceDrmBBMacInit(mac_key, 3);
		if(retv<0)
			return -3;
		retv = sceDrmBBMacUpdate(mac_key, data_buf, tp[5]);
		if(retv<0)
			return -4;
		retv = sceDrmBBMacFinal2(mac_key, (u8*)tp, version_key);
		if(retv<0)
			return -5;
	}

	if((tp[6]&4)==0){
		retv = sceDrmBBCipherInit(cipher_key, 1, 2, header_key, version_key, tp[4]>>4);
		if(retv<0)
			return -6;
		retv = sceDrmBBCipherUpdate(cipher_key, data_buf, tp[5]);
		if(retv<0)
			return -7;
		retv = sceDrmBBCipherFinal(cipher_key);
		if(retv<0)
			return -8;
	}

	if(tp[5]<block_size*2048){
		retv = lz_decomp(out_buf, 0x00100000, data_buf, 0);
	}else{
		memcpy(out_buf, data_buf, tp[5]);
		retv = 0x00008000;
	}

	return retv;
}

/*****************************************************************************/

int NpegClose(void)
{
	int k1 = pspSdkSetK1(0);

	sceIoClose(iso_fd);
	iso_fd = -1;

	pspSdkSetK1(k1);
	return 0;
}

/*****************************************************************************/

