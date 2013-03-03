
/*
 *  sign_eboot.c  -- sign your prx use game tag
 *                   written by tpu.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "utils.h"
#include "kirk_engine.h"
#include "psp_headers.h"

/*************************************************************/

typedef struct {
	u32 tag;
	u8  key[16];
	u32 code;
	u32 type;
} TAG_KEY;

TAG_KEY key_list[] = {
	{0xd91609f0, {0xD0,0x36,0x12,0x75,0x80,0x56,0x20,0x43,0xC4,0x30,0x94,0x3E,0x1C,0x75,0xD1,0xBF}, 0x5d, 2},
	{0xd9160af0, {0x10,0xA9,0xAC,0x16,0xAE,0x19,0xC0,0x7E,0x3B,0x60,0x77,0x86,0x01,0x6F,0xF2,0x63}, 0x5d, 2},
	{0xd9160bf0, {0x83,0x83,0xF1,0x37,0x53,0xD0,0xBE,0xFC,0x8D,0xA7,0x32,0x52,0x46,0x0A,0xC2,0xC2}, 0x5d, 2},
	{0xd91611f0, {0x61,0xB0,0xC0,0x58,0x71,0x57,0xD9,0xFA,0x74,0x67,0x0E,0x5C,0x7E,0x6E,0x95,0xB9}, 0x5d, 2},
	{0xd91612f0, {0x9e,0x20,0xe1,0xcd,0xd7,0x88,0xde,0xc0,0x31,0x9b,0x10,0xaf,0xc5,0xb8,0x73,0x23}, 0x5d, 2},
	{0xd91613f0, {0xEB,0xFF,0x40,0xD8,0xB4,0x1A,0xE1,0x66,0x91,0x3B,0x8F,0x64,0xB6,0xFC,0xB7,0x12}, 0x5d, 2},
	{0xd91614f0, {0xFD,0xF7,0xB7,0x3C,0x9F,0xD1,0x33,0x95,0x11,0xB8,0xB5,0xBB,0x54,0x23,0x73,0x85}, 0x5d, 2},
	{0xd91615f0, {0xC8,0x03,0xE3,0x44,0x50,0xF1,0xE7,0x2A,0x6A,0x0D,0xC3,0x61,0xB6,0x8E,0x5F,0x51}, 0x5d, 2},
	{0xd91624f0, {0x61,0xB7,0x26,0xAF,0x8B,0xF1,0x41,0x58,0x83,0x6A,0xC4,0x92,0x12,0xCB,0xB1,0xE9}, 0x5d, 2},
	{0xd91628f0, {0x49,0xA4,0xFC,0x66,0xDC,0xE7,0x62,0x21,0xDB,0x18,0xA7,0x50,0xD6,0xA8,0xC1,0xB6}, 0x5d, 2},
	{0xd91680f0, {0x2C,0x22,0x9B,0x12,0x36,0x74,0x11,0x67,0x49,0xD1,0xD1,0x88,0x92,0xF6,0xA1,0xD8}, 0x5d, 6},
	{0xd91681f0, {0x52,0xB6,0x36,0x6C,0x8C,0x46,0x7F,0x7A,0xCC,0x11,0x62,0x99,0xC1,0x99,0xBE,0x98}, 0x5d, 6},
};

int total_tags = sizeof(key_list)/sizeof(TAG_KEY);

/*************************************************************/

int WriteFile(const char *file, void *buf, int size)
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

void dump_psp_header(PSP_Header2 *h)
{
	int i;

	printf("       sig: %08x\n", h->signature);
	printf("  mod_attr: %04x\n", h->mod_attribute);
	printf(" comp_attr: %04x\n", h->comp_attribute);
	printf(" modver_lo: %02x\n", h->module_ver_lo);
	printf(" modver_hi: %02x\n", h->module_ver_hi);
	printf("   modname: %s\n"  , h->modname);
	printf("modversion: %02x\n", h->mod_version);
	printf("  segments: %02x\n", h->nsegments);
	printf("  elf_size: %08x\n", h->elf_size);
	printf(" file_size: %08x\n", h->psp_size);
	printf("boot_entry: %08x\n", h->boot_entry);
	printf("modinfo_pt: %08x\n", h->modinfo_offset);
	printf("  bss_size: %08x\n", h->bss_size);
	for(i=0; i<4; i++){
		printf("    seg[%d]: align %04x  addr %08x  size %08x\n", i, h->seg_align[i], h->seg_address[i], h->seg_size[i]);
	}

	printf("  devkit_ver: %08x\n", h->devkit_version);
	printf("decrypt_mode: %02x\n", h->decrypt_mode);
	printf("     padding: %02x\n", h->padding);
	printf("overlap_size: %04x\n", h->overlap_size);

}

/*************************************************************/

char *strtable;
int e_shnum;
Elf32_Shdr *section;

Elf32_Shdr *find_section(char *name)
{
	int i;

	for(i=0; i<e_shnum; i++){
		//printf("%2d: %s  type:%08x flags:%08x\n", i, strtable+section[i].sh_name, section[i].sh_type, section[i].sh_flags);
		if(strcmp(name, strtable+section[i].sh_name)==0)
			return &section[i];
	}

	return NULL;
}

void fix_reloc7(u8 *ebuf)
{
	Elf32_Rel *rel;
	int i, j, count;

	count = 0;
	for(i=0; i<e_shnum; i++){
		if(section[i].sh_type==0x700000A0){
			rel = (Elf32_Rel*)(ebuf+section[i].sh_offset);
			for(j=0; j<section[i].sh_size/sizeof(Elf32_Rel); j++){
				if((rel[j].r_info&0xFF)==7){
					rel[j].r_info = 0;
					count++;
				}
			}
		}
	}
}

void build_psp_header(PSP_Header2 *psph, u8 *ebuf, int esize)
{
	Elf32_Ehdr *elf;
	Elf32_Shdr *sh;
	Elf32_Phdr *ph;
	SceModuleInfo *modinfo;
	int i, j, shtab_size;

	elf = (Elf32_Ehdr*)(ebuf);

	section = (Elf32_Shdr *)(ebuf+elf->e_shoff);
	e_shnum = elf->e_shnum;

	shtab_size = e_shnum*elf->e_shentsize;
	if(elf->e_shoff+shtab_size>esize){
		printf("Invalid section table! ignore it.\n");
		e_shnum = 0;
	}else{
		strtable = (char*)(ebuf+section[elf->e_shstrndx].sh_offset);
		fix_reloc7(ebuf);
	}


	memset(psph, 0, sizeof(PSP_Header2));

	psph->signature = 0x5053507E;
	psph->mod_attribute = 0;
	psph->comp_attribute = 0;
	psph->module_ver_lo = 1;
	psph->module_ver_hi = 1;
	psph->mod_version = 1;
	psph->devkit_version = 0x06020010;
	psph->decrypt_mode = 9;
	psph->overlap_size = 0;

	psph->comp_size = esize;
	psph->_80 = 0x80;

	psph->boot_entry = elf->e_entry;
	psph->elf_size = esize;
	psph->psp_size = ((esize+15)&0xfffffff0)+0x150;

	// find sceModuleInfo struct
	ph = (Elf32_Phdr*)(ebuf+elf->e_phoff);
	sh = find_section(".rodata.sceModuleInfo");
	if(sh){
		psph->modinfo_offset = sh->sh_offset;
		modinfo = (SceModuleInfo*)(ebuf+sh->sh_offset);
	}else{
		// if no section table found, 
		// ph[0].p_paddr is the offset of .rodata.sceModuleInfo
		psph->modinfo_offset = ph[0].p_paddr;
		modinfo = (SceModuleInfo*)(ebuf+ph[0].p_paddr);
	}

	strcpy(psph->modname, modinfo->modname);

	j = 0;
	for(i=0; i<elf->e_phnum; i++){
		if(ph[i].p_type==PT_LOAD){
			if(j>3){
				printf("too many segments!\n");
				continue;
			}
			psph->seg_align[j]   = ph[i].p_align;
			psph->seg_address[j] = ph[i].p_vaddr;
			psph->seg_size[j]    = ph[i].p_memsz;
			// bss_size are caculated use last ph.
			psph->bss_size = ph[i].p_memsz-ph[i].p_filesz;
			j++;
		}
	}

	psph->nsegments = j;

}

/*************************************************************/


TAG_KEY *tkey;

u8 tag_key[0x100];

void build_tag_key(TAG_KEY *tk)
{
	int i;
	u32 *k7 = (u32*)tag_key;

	for(i=0; i<9; i++){
		memcpy(tag_key+0x14+(i*16), tk->key, 0x10);
		tag_key[0x14+(i*16)] = i;
	}

	k7[0] = KIRK_MODE_DECRYPT_CBC;
	k7[1] = 0;
	k7[2] = 0;
	k7[3] = tk->code;
	k7[4] = 0x90;

	kirk_CMD7(tag_key, tag_key, 0x90+0x14);
	//hex_dump("tag_keys", tag_key, 0x100);
}

void show_taglist(void)
{
	int i;

	for(i=0; i<total_tags; i++){
		printf("tag %2d: %08x  type: %d\n", i, key_list[i].tag, key_list[i].type);
	}
}

/*************************************************************/

u8 test_kirk1[32] = {
	0xca, 0x03, 0x84, 0xb1, 0xd9, 0x63, 0x47, 0x92, 0xce, 0xc7, 0x01, 0x23, 0x43, 0x72, 0x68, 0xac,
	0x77, 0xea, 0xec, 0xba, 0x6d, 0xaa, 0x97, 0xdf, 0xfe, 0x91, 0xb9, 0x39, 0x70, 0x99, 0x8b, 0x3a,
};

void build_psp_kirk1(u8 *kbuf, u8 *pbuf, int esize)
{
	KIRK_CMD1_HEADER *k1 = (KIRK_CMD1_HEADER *)kbuf;
	int i;

	memcpy(kbuf, test_kirk1, 32);

	k1->mode = KIRK_MODE_CMD1;
	k1->data_size = esize;
	k1->data_offset = 0x80;
	if(tkey->type==6)
		k1->ecdsa = 1;

	memcpy(kbuf+0x90, pbuf, 0x80);

	if(esize%16){
		for(i=0; i<(16-(esize%16)); i++){
			kbuf[0x110+esize+i] = 0xFF-i*0x11;
		}
	}

	//hex_dump("before kirk0", kbuf, 0x200);
	kirk_CMD0(kbuf, kbuf, esize);
	//hex_dump("after kirk0", kbuf, 0x200);

}

u8 test_k140[16] = {
	0x35, 0xfe, 0x4c, 0x96, 0x00, 0xb2, 0xf6, 0x7e, 0xf5, 0x83, 0xa6, 0x79, 0x1f, 0xa0, 0xe8, 0x86,
};

void build_psp_SHA1(u8 *ebuf, u8 *pbuf)
{
	u8 tmp[0x150];
	u32 *k4 = (u32*)tmp;
	int i;

	memset(tmp, 0, 0x150);

	for(i=0; i<0x40; i++){
		tmp[0x14+i] = ebuf[0x40+i]^tag_key[0x50+i];
	}
	memcpy(tmp+0xd0, pbuf, 0x80);
	//hex_dump("xor from:", tmp+0x14, 0x40);

	k4[0] = KIRK_MODE_ENCRYPT_CBC;
	k4[1] = 0;
	k4[2] = 0;
	k4[3] = tkey->code;
	k4[4] = 0x40;
	kirk_CMD4(tmp+0x80-0x14, tmp, 0x40+0x14);
	//hex_dump("kirk4:", tmp, 0x100);

	for(i=0; i<0x40; i++){
		tmp[0x80+i] ^=  tag_key[0x10+i];
	}

	memcpy(tmp+0xd0, pbuf, 0x80);
	memcpy(tmp+0xc0, pbuf+0xb0, 0x10);
	memcpy(tmp+0x70, test_k140, 0x10);
	memset(tmp, 0, 0x70);
	if(tkey->type==6)
		memcpy(tmp+0x50, ebuf+0x40+0x40, 0x20);
	memcpy(tmp+0x08, tag_key, 0x10);
	k4[0] = 0x014c;
	k4[1] = tkey->tag;

	//hex_dump("before SHA1:", tmp, 0x150);
	kirk_CMD11(tmp, tmp, 0x150);
	//hex_dump("after SHA1:", tmp, 0x150);


	memcpy(tmp+0x5c, test_k140, 0x10);
	memcpy(tmp+0x6c, tmp, 0x14);


	k4 = (u32*)(tmp+0x48);
	k4[0] = KIRK_MODE_ENCRYPT_CBC;
	k4[1] = 0;
	k4[2] = 0;
	k4[3] = tkey->code;
	k4[4] = 0x60;
	kirk_CMD4(tmp+0x48, tmp+0x48, 0x60+0x14);

	memset(tmp, 0, 0x5c);
	if(tkey->type==6)
		memcpy(tmp+0x3c, ebuf+0x40+0x40, 0x20);
	k4 = (u32*)tmp;
	k4[0] = tkey->tag;

	//hex_dump("reorder:", tmp, 0x150);

	memcpy(ebuf+0x000, tmp+0xd0, 0x80);
	memcpy(ebuf+0x080, tmp+0x80, 0x30);
	memcpy(ebuf+0x0b0, tmp+0xc0, 0x10);
	memcpy(ebuf+0x0c0, tmp+0xb0, 0x10);
	memcpy(ebuf+0x0d0, tmp+0x00, 0x5c);
	memcpy(ebuf+0x12c, tmp+0x6c, 0x14);
	memcpy(ebuf+0x140, tmp+0x5c, 0x10);

	//hex_dump("PSP header:", ebuf, 0x150);
}

/*************************************************************/

PSP_Header2 psp_header;

int main(int argc, char *argv[])
{
	FILE *fp;
	u8 *ebuf;
	int esize;

	int ap, do_list_tag, do_fake_sign, select_tag;
	char *input_name, *output_name;

	input_name = NULL;
	output_name = NULL;
	do_list_tag = 0;
	select_tag = -1;
	do_fake_sign = 0;
	ap = 1;

	if (argc<2) {
		printf("Usage: sign_eboot -l\n");
		printf("    list all tags\n");
		printf("Usage: sign_eboot -tn elf_file signed_file\n");
		printf("    sign your elf file. -tn select a tag to use.\n");
		return -1;
	}

	while(ap<argc){
		if(argv[ap][0]=='-'){
			if(argv[ap][1]=='l'){
				do_list_tag = 1;
			}else if(argv[ap][1]=='t'){
				select_tag = atoi(&argv[ap][2]);
			}else if(argv[ap][1]=='f'){
				do_fake_sign = 1;
			}else{
				printf(" unkonw param: %s\n", argv[ap]);
				return -1;
			}
		}else{
			if(input_name==NULL){
				input_name = argv[ap];
			}else if(output_name==NULL){
				output_name = argv[ap];
			}
		}

		ap += 1;
	}

	if(do_list_tag==1){
		show_taglist();
		return 0;
	}

	if(select_tag<0 || select_tag>=total_tags){
		printf("invalid tag index!\n");
		show_taglist();
		return -1;
	}

	tkey = &key_list[select_tag];

	fp = fopen(input_name, "rb");
	if(fp==NULL){
		printf("Open file %s failed!\n", input_name);
		exit(-1);
	}

	fseek(fp, 0, SEEK_END);
	esize = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	ebuf = malloc(esize+4096);
	memset(ebuf, 0, esize+4096);

	fread(ebuf+0x150, esize, 1, fp);
	fclose(fp);

	if(*(u32*)(ebuf+0x150)!=0x464c457f) {
		printf("%s: not a ELF file.\n", argv[1]);
		return -1;
	}
	printf("Load %s ...\n", input_name);
	printf("Use tag %08x\n", tkey->tag);

	build_psp_header(&psp_header, ebuf+0x150, esize);

	build_psp_kirk1(ebuf+0x40, (u8*)&psp_header, esize);

	build_tag_key(tkey);

	build_psp_SHA1(ebuf, (u8*)&psp_header);

	esize = (esize+15)&~15;

	WriteFile(output_name, ebuf, esize+0x150);
	printf("Save %s .\n", output_name);

	return 0;
}

