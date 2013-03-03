
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "utils.h"

#include "kirk_engine.h"
#include "amctrl.h"

/*****************************************************************************/

int NpegOpen(char *name, u8 *header, u8 *table, int *table_size);
int NpegReadBlock(u8 *data_buf, u8 *out_buf, int block);
int NpegClose(void);

/*****************************************************************************/

u8 table[0x400000];
u8 data_buf[0x100000];
u8 decrypt_buf[0x200000];
u8 header[0x100];

/*****************************************************************************/

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

/*****************************************************************************/

int main(int argc, char *argv[])
{
	int table_size, retv;
	int blocks, block_size;
	int start, end, iso_size;
	int i;
	char iso_name[64];
	FILE *iso_fd;

	printf("NP Decryptor for PC. Writen by tpu.\n");
	kirk_init();

	retv = NpegOpen("NP.PBP", header, table, &table_size);
	if(retv<0){
		retv = NpegOpen("EBOOT.PBP", header, table, &table_size);
		if(retv<0){
			printf("NpegOpen Error! %08x\n", retv);
			return -1;
		}
	}

	write_file("header.bin", header, 0x100);
	printf("table_size=%d\n", table_size);
	printf("Dumped header.\n\n");

	start = *(u32*)(header+0x54); // 0x54 LBA start
	end   = *(u32*)(header+0x64); // 0x64 LBA end
	iso_size = (end-start+1)*2048;

	block_size = *(u32*)(header+0x0c); // 0x0C block size?
	block_size *= 2048;

	printf("ISO name: %s.iso\n", header+0x70);
	printf("ISO size: %d MB\n", iso_size/0x100000);

	sprintf(iso_name, "%s.iso", header+0x70);
	iso_fd = fopen(iso_name, "wb");
	if(iso_fd==NULL){
		printf("Error creating %s\n", iso_name);
	}

	blocks = table_size/32;

	for(i=0; i<blocks; i++){
		retv = NpegReadBlock(data_buf, decrypt_buf, i);
		if(retv<=0){
			printf("Error %08x reading block %d\n", retv, i);
			break;
		}
		fwrite(decrypt_buf, retv, 1, iso_fd);

		if((i&0x0f)==0){
			printf("Dumping... %3d%% %d/%d    \r", i*100/blocks, i, blocks);
		}
	}
	printf("\n\n");

	fclose(iso_fd);
	NpegClose();

	return 0;
}

