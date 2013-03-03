

/**************************************************/
/* error codes */
/**************************************************/
#define SCE_GAMEDATA_ERROR_INVALID_ARG          0x80510201
#define SCE_GAMEDATA_ERROR_MFILE                0x80510202
#define SCE_GAMEDATA_ERROR_BADF                 0x80510203
#define SCE_GAMEDATA_ERROR_INVALID_FORMAT       0x80510204
#define SCE_GAMEDATA_ERROR_UNKNOWN_VERSION      0x80510205
#define SCE_GAMEDATA_ERROR_SECURE_INSTALL_ID    0x80510206
#define SCE_GAMEDATA_ERROR_BROKEN_DATA          0x80510207

/**************************************************/
/* ioctl commands */
/**************************************************/
#define SCE_GAMEDATA_IOCTL_BASE                 (0x41 << 20)
#define SCE_GAMEDATA_SET_SECURE_INSTALL_ID      (SCE_GAMEDATA_IOCTL_BASE|0x01)


typedef struct {
	u8 key[16];      // 00
	u32 version;     // 10: always 00
	u32 file_size;   // 14
	u32 block_size;  // 18
	u32 data_offset; // 1C
	u8 unk_20[16];
}PGD_DESC;


typedef struct {
	PGD_DESC pgdesc;
	u8 pgd_key[0x10];
	u32 flag;        // 0x40
	u32 flag_open;   // 0x44
	u32 pgd_offset;  // 0x48
	int seek_offset; // 0x4C
	u32 data_offset; // 0x50
	u32 table_offset;// 0x54
	u32 unk_58;
	u32 unk_5c;
}PspIoHookParam;


typedef struct
{
	u32 unk_00;
	u32 fs_num;
	PSpIoDrvFuncs *funcs;
	PspIoHookParam *hp;
}PspIoHookFileArg;





int dnas_sema;



u8 loc_1A90[] = {0xED,0xE2,0x5D,0x2D,0xBB,0xF8,0x12,0xE5,0x3C,0x5C,0x59,0x32,0xFA,0xE3,0xE2,0x43};
u8 loc_1AA0[] = {0x27,0x74,0xFB,0xEB,0xA4,0xA0,   1,0xD7,   2,0x56,0x9E,0x33,0x8C,0x19,0x57,0x83};

u8 loc_1AC0[0x640];

// dnas_init
int hook_func0_E8()
{
	return 0;
}

// dnas_exit
int hook_func1_F0()
{
	return 0;
}

// dnas_match
int hook_func2_F8(PspIoHookFileArg *file, int a1, int a2)
{
	return (a2>>30)&1;
}

// dnas_open
int hook_func3_100(PspIoHookFileArg *file, char *name, int flag, int mode)
{
	s1 = a2;
	s5 = a3;
	s4 = a1;
	s3 = a0;
	s7 = 0xffffffff;

	if(flag&2)
		return 0x80510201;

	s2 = loc_1780;
	s6 = (flag&0x04000000)? 1 : 2;

	// max open files: 8
	a1 = *(u32*)(s2+0x304);
	if(a1>7)
		return 0x80510202;

	retv = file->funcs->IoOpen(file->fs_num, name, flag, mode);
	if(retv<0)
		return retv;

	*(u32*)(s2+0x304) += 1;
	s2 = retv;

	retv = file->funcs->IoIoctl(file->fs_num, 0x00208002, 0, 0, 0, 0);
	if(retv<0){
		retv = file->funcs->IoIoctl(file->fs_num, 0x00208011, 0, 0, 0, 0);
		if(retv<0){
			retv = 0x80020146;
			goto _error;
		}
	}

	t9 = loc_1780;
	s1 = t9;
	s0 = 0;
	v1 = t9+0x40;

	s7 = -1;
	while(s0<8){
		a3 = *(u32*)(v1);
		v1 += 0x60;
		if(a3==0){
			memset(s1, 0, 0x60);
			s7 = s0;
			*(u32*)(s1+0x40) = s6;
			break;
		}
		s0 += 1;
		s1 += 0x60;
	}
	if(s7<0){
		// xxxx
		retv = 0x80510202;
		goto _error:
	}

	s0 = s7*2;
	a1 = s0+s7; // s7*3
	v1 = a1<<5; // s7*3*32
	fp = v1+a2; // a2+s7*0x60

	*(u32*)(fp+0x44) = 0;
	file->unk_0c = fp;
	return s2;

_error:
	if(s2>=0){
		file->funcs->IoClose(file->fs_num);
		*(u32*)(s2+0x304) -= 1;
		if(s7){
			t5 = s7*2;
			t4 = t5+s7; // s7*3
			t3 = t4<<5; // s7*3*32
			a0 = t3+v1; // t3+s7*0x60
			memset(a0, 0, 0x60);
		}
	}

	return retv;
}

// dnas_close
int hook_func4_35C(PspIoHookFileArg *file)
{
	v1 = a0;

	file->funcs->IoClose(file->fs_num);

	s0 = file->unk_0c;

	memset(s0, 0, 0x60);
	*(u32*)(s2+0x304) -= 1;

	return 0;
}

// dnas_lseek
int hook_func7_3F4(PspIoHookFileArg *file, int offset, int mode)
{
	s3 = file->unk_0c;

	a2 = *(u32*)(s3+0x44);
	if((a2&8)==0)
		return 0x80510206;

	if(mode<0 || mode>2)
		return 0x80510201;

	if(mode==SEEK_CUR){
		v0 = *(u32*)(s3+0x4c);
		offset += v0;
	}else if(s2==SEEK_END){
		v0 = *(u32*)(s3+0x14);
		offset += v0;
	}

	file_size = *(u32*)(s3+0x14);
	if(offset>file_size){
		offset = file_size;
	}
	*(u32*)(s3+0x4c) = offset;

	return offset;
}



int sub_12B4(u8 *buf, int size, u32 seed, u8 *vkey, u8 *hkey, int type)
{
	CIPHER_KEY ckey;

	v1 = a3; // vkey
	t2 = t1; // type
	s0 = a0; // buf
	s1 = a1; // size

	retv = sceDrmBBCipherInit(&ckey, type, 2, hkey, vkey, seed);
	if(retv<0)
		return retv;

	retv = sceDrmBBCipherUpdate(&ckey, buf, size);
	if(retv<0)
		return retv;

	retv = sceDrmBBCipherFinal(&ckey);
	if(retv<0)
		return retv;

	return 0;
}



int sub_1368(u8 *buf, int size, u8 *key, u8 *bbmac, int type)
{
	u8 tmp[0x10];
	MAC_KEY mkey;
	int retv;

	if(bbmac==0)
		return SCE_GAMEDATA_ERROR_INVALID_ARG;

	retv = sceDrmBBMacInit(&mkey, type);
	if(retv<0)
		return SCE_GAMEDATA_ERROR_BROKEN_DATA;

	retv = sceDrmBBMacUpdate(&mkey, buf, size);
	if(retv<0)
		return SCE_GAMEDATA_ERROR_BROKEN_DATA;

	retv = sceDrmBBMacFinal(&mkey, tmp, key);
	if(retv<0)
		return SCE_GAMEDATA_ERROR_BROKEN_DATA;

	if(memcmp(bbmac, tmp, 0x10))
		return SCE_GAMEDATA_ERROR_BROKEN_DATA;

	memset(tmp, 0, 0x10);

	return 0;
}




int _pgd_open_1124(u8 *buf, u8 *vkey, int flag)
{
	v1 = 0x80510201;
	type = 2;
	s3 = a2;
	s2 = 0;
	s1 = a1;
	s0 = a0;

	if(key==NULL)
		return SCE_GAMEDATA_ERROR_INVALID_ARG;

	// check "\0PGD"
	if(*(u32*)(buf+0)!=0x44475000)
		return SCE_GAMEDATA_ERROR_INVALID_FORMAT;
	if(*(u32*)(buf+4)!=0x00000001)
		return SCE_GAMEDATA_ERROR_UNKNOWN_VERSION;

	if(*(u32*)(buf+8)==0x00000000){
		if(flag&4)
			return SCE_GAMEDATA_ERROR_INVALID_FORMAT;
	}else if(*(u32*)(buf+8)==0x00000001){
		flag |= 4;
		type = 1;
	}else
		return SCE_GAMEDATA_ERROR_INVALID_FORMAT;

	if(flag&2)
		fkey = 0x1A90;
	if(flag&1)
		fkey = 0x1AA0;
	if(fkey==0)
		return SCE_GAMEDATA_ERROR_INVALID_ARG;

	//    sub_1368(u8 *buf, int size, u8 *key, u8 *bbmac, int type)
	retv = sub_1368(buf, 0x80, fkey, buf+0x80, type);
	if(retv<0)
		return SCE_GAMEDATA_ERROR_INVALID_FORMAT;

	retv = sub_1368(buf, 0x70, vkey, buf+0x70, type);
	if(retv<0)
		return SCE_GAMEDATA_ERROR_SECURE_INSTALL_ID;

	//     sub_12B4(u8 *buf, int size, u32 seed, u8 *vkey, u8 *hkey, int type)
	retv = sub_12B4(buf+0x30, 0x30, 0, vkey, buf+0x10, type);
	if(retv<0)
		return SCE_GAMEDATA_ERROR_UNKNOWN_VERSION;

	if(*(u32*)(buf+0x40))
		return SCE_GAMEDATA_ERROR_UNKNOWN_VERSION;

	if(*(u32*)(buf+0x48)!=0x0400)
		return SCE_GAMEDATA_ERROR_INVALID_FORMAT;

	flag |= 8;

	return flag;
}

/*
 * PGD header:
 * 00: PGD
 * 10: header_key
 * 20: unk
 * 30: encrypted data
 * 40:
 * 50:
 * 60: MAC of table
 * 70: MAC of 00-60
 * 80: MAC of 00-70
 *
 */

int sub_B60(PspIoHookFileArg *file, u8 *key)
{
	u8 tmp[16];

	s1 = file->unk_0c;
	s5 = loc_1AC0;

	memcpy(s1+0x30, key, 0x10);

	offset = *(u32*)(s1+0x48);
	retv = file->funcs->IoLseek(file->fs_num, offset, SEEK_SET);
	if(retv!=offset)
		goto _exit;

	retv = file->funcs->IoRead(file->fs_num, s5, 0x90);
	if(retv<0x90)
		goto _exit;

	flag = *(u32*)(s1+0x40);
	retv = _pgd_open_1124(s5, key, flag);
	if(retv<0 || retv&8==0){
		*(u32*)(s1+0x44) = 0;
		goto _exit;
	}
	*(u32*)(s1+0x44) = retv;

	memcpy(s1, s5+0x30, 0x30);
	memcpy(tmp, s5+0x60, 0x10);

	fp = (retv&4)? 1 : 2 ;

	t0 = *(u32*)(s1+0x14); // file_size
	t9 = *(u32*)(s1+0x18); // block_size 0x00000400

	s2 = t0+0x0f;
	s2 &= 0xfffffff0; // file_size

	a1 = s2+t9;
	v1 = a1-1; // file_size+block_size-1;
	a2 = -t9; // 0xfffffc00;
	s7 = v1&a2; // s7 = file_size_block 
	t8 = t9>>4;
	s7 = s7/t8; // s7 = table_size;

	t5 = *(u32*)(s1+0x48); // PGD offset
	t6 = *(u32*)(s1+0x1C); // data offset in PGD
	t4 = s2+0x90;
	t3 = t6+t5;
	s0 = t4+t5; // PGD_offset+0x90+file_size
	*(u32*)(s1+0x50) = t3; //  data offset in EDATA
	*(u32*)(s1+0x54) = s0; // table offset in EDATA
	t2 = 0x0007ffff;
	if(t2<s7)
		return 0;

	retv = sceDrmBBMacInit(&mkey, fp);
	if(retv<0)
		goto _exit;

	retv = file->funcs->IoLseek(file->fs_num, s0, SEEK_SET);
	if(retv<0)
		goto _exit;

	for(i=0; i<s7; i+=0x400){
		s0 = s7-i;
		if(s0>0x400)
			s0 = 0x400;
		retv = file->funcs->IoRead(file->fs_num, s5, s0);
		if(retv<s0)
			goto _exit;

		retv = sceDrmBBMacUpdate(&mkey, s5, s0);
		if(retv<0)
			goto _exit;
	}

	retv = sceDrmBBMacFinal(loc_20D8, s5, s4);
	if(retv<)
		goto _exit;

	retv = memcmp(s5, tmp, 0x10);
	memset(tmp, 0, 0x10);
	if(retv){
		retv = 0x80510207;
		goto _exit;
	}

	return 0;

_exit:
	if(retv<0)
		return retv;
	else
		return 0x80510204;
}

// set pgd offset
int sub_E3C(PspIoHookFileArg *file, u32 a1)
{
	s0 = file->unk_0c;
	v0 = *(u32*)(s0+0x48);
	if(v0==a1)
		return 0;

	*(u32*)(s0+0x44) = 0;
	*(u32*)(s0+0x48) = a1;

	return 0;
}

// set 0x58
int sub_EB8(PspIoHookFileArg *file, u32 a1)
{
	s0 = file->unk_0c;
	*(u32*)(s0+0x58) = a1;

	return 0;
}

// seek and read
int sub_F28(PspIoHookFileArg *file, u8 *buf, int offset, int size)
{

	retv = file->funcs->IoLseek(file->fs_num, offset, SEEK_SET);
	if(retv==offset){
		retv = file->funcs->IoRead(file->fs_num, buf, size);
		if(retv<size)
			retv = 0x80010005;
	}else{
		retv = 0x8001001D;
	}

	return retv;
}


int sub_1010(PspIoHookFileArg *file)
{
	s0 = file->unk_0c;
	a2 = *(u32*)(s0+0x44);
	if(a2&8==0)
		return = SCE_GAMEDATA_ERROR_SECURE_INSTALL_ID;

	return 0;
}

int sub_1094(PspIoHookFileArg *file)
{
	s0 = file->unk_0c;
	a2 = *(u32*)(s0+0x44);
	if(a2&8==0)
		return = SCE_GAMEDATA_ERROR_SECURE_INSTALL_ID;

	s1 = *(u32*)(s0+0x14);
	return s1;
}


int _dnas_ioctl_9F0(PspIoHookFileArg *file, int cmd, int a2, int a3, int t0)
{
	s0 = a0;
	v0 = cmd-0x04100001;

	retv = SCE_GAMEDATA_ERROR_INVALID_ARG;
	switch(v0){
	case 0:
		// pgd open
		if(a2<1 || a3>15)
			break;
		retv = sub_B60(a0, a2);
		break;
	case 1:
		// set pgd offset
		if(a2<1 || a3>4)
			break;
		retv = sub_E3C(a0, a2);
		break;
	case 2:
		retv = sceKernelApplicationType();
		if(retv!=a2){
			retv = SCE_GAMEDATA_ERROR_INVALID_ARG;
			break;
		}
		retv = sub_EB8(a0, 1);
		break;
	case 3:
		retv = sub_EB8(a0, 0);
		break;
	case 4:
		// seek and read
		if(a2<1 || a3>8 || t0==0)
			break;
		a3 = *(u32*)(a2+4);
		if(t1<a3)
			break;
		retv = sub_F28(a0, t0);
		break;
	case 5:
		// check
		retv = sub_1010(a0);
		break;
	case 15:
		// get file_size
		retv = sub_1094(a0);
		break;
	default:
		// IoIoctl
		t5 = *(u32*)(s0+8);
		a0 = *(u32*)(s0+4);
		s0 = *(u32*)(t5+0x1c);
		retv = s0(a0);
		break;
	}

	return retv;
}

/**************************************************/


PspIoDrv hook_drv = {
	.name		= "gamedata",
	.dev_type	= 0,
	.unk2		= 0,
	.name2		= "filemgr_dnas",
	.funcs		= &PspIoHookFuncs,
};


int module_start(int argc, void *args)
{
	dnas_sema = sceKernelCreateSema("SceIoFilemgrDNAS1", 0, 1, 1, 0);
	if(dnas_sema<0){
		memset(&loc_1780, 0, 0x330);
		memset(&loc_1AC0, 0, 0x640);
		return 1;
	}

	sceIoAddHook(&hook_drv);
	return 0;
}

