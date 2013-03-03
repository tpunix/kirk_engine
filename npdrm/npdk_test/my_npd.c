
#include <pspsdk.h>
#include <pspkernel.h>
#include <pspdebug.h>
#include <pspctrl.h>
#include <pspiofilemgr.h>
#include <psploadcore.h>
#include <psppower.h>

#include <stdio.h>
#include <string.h>

PSP_MODULE_INFO("New_NpDecrypt", 0x1000, 1, 1);

/*****************************************************************************/

int NpegOpen(char *name, u8 *header, u8 *unk, u8 *table, int *table_size);
int NpegReadBlock(u8 *data_buf, u8 *out_buf, int block);
int NpegClose(void);

/*****************************************************************************/

u8 *table       = (u8*)0x09000000;
u8 *data_buf    = (u8*)0x09400000;
u8 *decrypt_buf = (u8*)0x09500000;
u8 *header      = (u8*)0x09700000;
u8 *actdat      = (u8*)0x09700100;

/*****************************************************************************/

#define printf pspDebugScreenPrintf

int sceGeEdramGetAddr(void)
{
	return 0x04000000;
}

/*****************************************************************************/

int load_start_module(char *name, int args, void *argv)
{
	int mid;

	mid = sceKernelLoadModule(name, 0, NULL);
	if(mid>0)
		mid = sceKernelStartModule(mid, args, argv, NULL, NULL);

	return mid;
}

int write_file(char *name, u8 *buf, int size)
{
	int fd;

	fd = sceIoOpen(name, PSP_O_WRONLY|PSP_O_CREAT|PSP_O_TRUNC, 0777);
	if(fd<0)
		return fd;

	sceIoWrite(fd, buf, size);
	sceIoClose(fd);

	return 0;
}

void hex_dump(char *str, u8 *buf, int size)
{
	int i;

	if(str)
		printk("%s:", str);

	for(i=0; i<size; i++){
		if((i%16)==0){
			printk("\n%4x:", i);
		}
		printk(" %02x", buf[i]);
	}
	printk("\n\n");
}


/*****************************************************************************/

int main_thread(int args, void *argv)
{
	int table_size, retv;
	int blocks, block_size;
	int start, end, iso_size;
	int scr_x, scr_y;
	char iso_name[64], *p;
	int iso_fd, i;
	SceCtrlData pad;

	p = strrchr(argv, '/');
	if(p)
		*p = 0;
	sceIoChdir(argv);

	pspDebugScreenInit();

	pspDebugScreenSetTextColor(0x000000ff);
	printf("NP Decryptor by CipherUpdate & kono.\n");
	printf("New Version by tpu.\n\n");
	pspDebugScreenSetTextColor(0x00ffffff);

	retv = load_start_module("npdrm.prx", args, argv);
	if(retv<0){
		printf("Error loading module npdrm: %08x\n", retv);
		sceKernelDelayThread(4000000);
		goto _exit;
	}
	printf("Modules loaded.\n");

	retv = NpegOpen("NP.PBP", header, actdat, table, &table_size);
	if(retv<0){
		printf("NpegOpen Error! %08x\n", retv);
		goto _exit;
	}

	write_file("header.bin", header, 0x100);
	write_file("lookup_table.bin", table, table_size);
	printf("Dumped header and lookup_table.\n\n");

	start = *(u32*)(header+0x54); // 0x54 LBA start
	end   = *(u32*)(header+0x64); // 0x64 LBA end
	iso_size = (end-start+1)*2048;

	block_size = *(u32*)(header+0x0c); // 0x0C block size?
	block_size *= 2048;

	printf("ISO name: %s.iso\n", header+0x70);
	printf("ISO size: %d MB\n", iso_size/0x100000);
	printf("Press 'X' to save it, and 'O' to exit.\n");

	while(1){
		sceCtrlReadBufferPositive(&pad, 1);
		if(pad.Buttons&PSP_CTRL_CROSS)
			break;
		if(pad.Buttons&PSP_CTRL_CIRCLE)
			sceKernelExitVSHVSH (NULL);
		sceKernelDelayThread(8000);
	}

	scr_x = pspDebugScreenGetX();
	scr_y = pspDebugScreenGetY();

	sprintf(iso_name, "ms0:/ISO/%s.iso", header+0x70);
	iso_fd = sceIoOpen(iso_name, PSP_O_WRONLY|PSP_O_CREAT|PSP_O_TRUNC, 0777);
	if(iso_fd<0){
		printf("Error creating %s - 0x%08X\n", iso_name, iso_fd);
	}

	blocks = table_size/32;

	for(i=0; i<blocks; i++){
		retv = NpegReadBlock(data_buf, decrypt_buf, i);
		if(retv<=0){
			printf("Error %08x reading block %d\n", retv, i);
			break;
		}
		sceIoWrite(iso_fd, decrypt_buf, retv);

		if((i&0x0f)==0){
			pspDebugScreenSetXY(scr_x, scr_y);
			printf("Dumping... %3d%% %d/%d    \n", i*100/blocks, i, blocks);
			sceCtrlReadBufferPositive(&pad, 1);
		}

		scePowerTick(0);
	}
	sceIoClose(iso_fd);
	NpegClose();
	printf("\n");

_exit:
	printf("Process finished. Press any key to exit.\n");
	while(1){
		sceCtrlReadBufferPositive(&pad, 1);
		if(pad.Buttons&0xF3F9)
			break;
		sceKernelDelayThread(12000);
	}

	sceKernelExitVSHVSH (NULL);
	return 0;
}

int module_start(SceSize args, void* argp)
{
	int thid;

	thid = sceKernelCreateThread("main_thread", (void*)main_thread, 0x1A, 0x4000, 0, NULL);

	if(thid>=0) {
		sceKernelStartThread(thid, args, argp);
	}

	return 0;
}

int module_stop(SceSize args, void *argp)
{
	return 0;
}

