

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "kirk_engine.h"
#include "amctrl.h"
#include "crypto.h"
#include "ecdsa.h"
#include "utils.h"



u8 pubkey_edat_x[20] = {0x1F,0x07,0x2B,0xCC,0xC1,0x62,0xF2,0xCF,0xAE,0xA0,0xE7,0xF4,0xCD,0xFD,0x9C,0xAE,0xC6,0xC4,0x55,0x21};
u8 pubkey_edat_y[20] = {0x53,0x01,0xF4,0xE3,0x70,0xC3,0xED,0xE2,0xD4,0xF5,0xDB,0xC3,0xA7,0xDE,0x8C,0xAA,0xE8,0xAD,0x5B,0x7D};


u8 edat_aeskey[16] = {0xBA,0x87,0xE4,0xAB,0x2C,0x60,0x5F,0x59,0xB8,0x3B,0xDB,0xA6,0x82,0xFD,0xAE,0x14};

extern ECDSA_PARAM ecdsa_app;
extern u8 priv_key_edata[];

int verbose = 0;

/*************************************************************/

int edata_check_ecdsa(u8 *edata_buf)
{
	u8 sha1_hash[20];
	int retv;

	printf("EDATA ID: %s\n", (char*)(edata_buf+0x10));

	ecdsa_set_curve(&ecdsa_app);
	ecdsa_set_pub(pubkey_edat_x, pubkey_edat_y);

	SHA1(edata_buf, 0x58, sha1_hash);
	retv = ecdsa_verify(sha1_hash, edata_buf+0x58, edata_buf+0x6c);
	if(retv==0){
		//printf("ECDSA verify passed!\n");
	}else{
		printf("edata_check_ecdsa: ECDSA verify failed!\n");
	}

	return retv;
}


int edata_sign_free(u8 *edata_buf, u8 *pgd_key)
{
	MAC_KEY mkey;
	AES_ctx aes;
	u8 sha1_hash[20], license_key[16];
	int flag, i;

	printf("re-sign EDATA ...\n");

	flag = *(u8*)(edata_buf+15);

	// get license_key
	if(flag&1){
		sceDrmBBMacInit(&mkey, 3);
		sceDrmBBMacUpdate(&mkey, edata_buf, 0x80);
		bbmac_getkey(&mkey, edata_buf+0x80, license_key);
		if(verbose) hex_dump("license key", license_key, 16);
	}

	// change to use free license
	*(u32*)(edata_buf+8) = 0x01000000;

	// build ecdsa
	ecdsa_set_curve(&ecdsa_app);
	ecdsa_set_priv(priv_key_edata);
	SHA1(edata_buf, 0x58, sha1_hash);
	ecdsa_sign(sha1_hash, edata_buf+0x58, edata_buf+0x6c, NULL);

	// build BBMAC
	if(flag&1){
		sceDrmBBMacInit(&mkey, 3);
		sceDrmBBMacUpdate(&mkey, edata_buf, 0x80);
		sceDrmBBMacFinal(&mkey, edata_buf+0x80, license_key);
		bbmac_build_final2(3, edata_buf+0x80);
	}

	// build PGD key
	sceNpDrmGetFixedKey(pgd_key, (char*)(edata_buf+16), 0x01000000);
	if(verbose) hex_dump("get_fixed_key", pgd_key, 16);

	if(flag&1){
		for(i=0; i<16; i++){
			pgd_key[i] ^= license_key[i];
		}
	}

	AES_set_key(&aes, edat_aeskey, 128);
	AES_decrypt(&aes, pgd_key, pgd_key);
	if(verbose) hex_dump("new PGD key", pgd_key, 16);

	return 0;
}

/*************************************************************/


int pgd_decrypt(u8 *pgd_buf, int pgd_size, int pgd_flag, u8 *pgd_vkey);
int pgd_encrypt(u8 *pgd_buf, int pgd_flag, u8 *vkey);

int free_edata(char *edata_name)
{
	u8 *edata_buf;
	u32 *hd;
	u8 pgd_key[16];
	int retv, edata_size, pgd_offset;

	edata_buf = load_file(edata_name, &edata_size);
	if(edata_buf==NULL){
		printf("Open input file <%s> error!\n", edata_name);
		return -1;
	}

	hd = (u32*)edata_buf;
	if(hd[0]!=0x50535000 || hd[1]!=0x54414445){
		free(edata_buf);
		return -1;
	}
	printf("\nProcess %s ...\n", edata_name);


	retv = edata_check_ecdsa(edata_buf);
	if(retv)
		return retv;

	edata_sign_free(edata_buf, pgd_key);


	// PGD
	pgd_offset = *(u32*)(edata_buf+0x0c);
	pgd_offset &= 0x00ffffff;

	retv = pgd_decrypt(edata_buf+pgd_offset, edata_size-pgd_offset, 2, NULL);
	if(retv<0){
		printf("pgd_decrypt failed! %08x(%d)\n", retv, retv);
		return -1;
	}

	retv = pgd_encrypt(edata_buf+pgd_offset, 2, pgd_key);
	if(retv<0){
		printf("pgd_encrypt failed! %08x(%d)\n", retv, retv);
		return -1;
	}

	write_file(edata_name, edata_buf, edata_size);
	printf("write %s\n\n", edata_name);

	return 0;
}

int main(int argc, char *argv[])
{
	printf("\n");
	printf("freedata: convert EDAT file to use fixed license. writen by tpu.\n");
	printf("-------------------------------------------------------------\n");
	printf("\n");

	if(argc==2 && (strcmp(argv[1], "-v")==0))
		verbose = 1;

	return walk_dir(".", free_edata, 0);
}

