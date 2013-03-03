


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/stat.h>
#include <io.h>



typedef unsigned char u8;

/**************************************************************/

char ownisgraph (u8 c)
{
    if ( c >= 0x21 && c <= 0x7e )
        return 1;

    return 0;
}

void hex_dump(const char *str, void *addr, int size)
{
	int i;
	u8 *p = (u8*)addr;
	
	if (addr == NULL) {
		printf("hexdump: <NULL>\n");
		return;
	}

	if (size == 0) {
		printf("hexdump: size 0\n");
		return;
	}

	if(str)
		printf("%s:\n", str);

#if 0
	printf("Address:   ");
	i=0; for(;i<16; ++i) {
		if (i == 8)
			printf("- ");
		
		printf("%02X ", i);
	}

	i=0; for(;i<16; ++i) {
		printf("%1X", i);
	}

	printf("\n-----------------------------------------------------------------------------\n");
#endif

	i=0;
	printf("0x%08X ", i);
	
	for(; i<size; ++i) {
		if (i != 0 && i % 16 == 0) {
			int j;

			for(j=16; j>0; --j) {
				if(ownisgraph(p[i-j])) {
					printf("%c", p[i-j]);
				} else {
					printf(".");
				}
			}
			printf("\n0x%08X ", i);
		}

		if (i != 0 && i % 8 == 0 && i % 16 != 0) {
			printf("- ");
		}

		printf("%02X ", p[i]);
	}

	int rest = (16-(i%16));

	rest = rest == 16 ? 0 : rest;
	int j; for(j=0; j<rest; j++) {
		if (j+(i%16) == 8)
			printf("  ");
		printf("   ");
	}

	rest = i % 16;
	rest = rest == 0 ? 16 : rest;

	for(j=rest; j>0; --j) {
		if(ownisgraph(p[i-j])) {
			printf("%c", p[i-j]);
		} else {
			printf(".");
		}
	}

	printf("\n\n");
}


/**************************************************************/

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

u8 *load_file(char *name, int *size)
{
	FILE *fp;
	u8 *buf;

	fp = open_file(name, size);
	if(fp==NULL)
		return NULL;
	buf = malloc(*size);
	fread(buf, *size, 1, fp);
	fclose(fp);

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

/**************************************************************/

int walk_dir(char *dname, void *func_ptr, int verbose)
{
	DIR *pdir;
	struct dirent *d;
	struct stat statbuf;
	char fname[256];
	int i, ndir;
	int (*f_process_file)(char *) = func_ptr;

	/* process file */
	memset(&statbuf, 0, sizeof(statbuf));
	stat(dname, &statbuf);
	if((statbuf.st_mode&S_IFMT) != S_IFDIR){
		if(func_ptr!=NULL)
			return f_process_file(dname);
		else
			return 0;
	}

	/* open directory */
	pdir = opendir(dname);
	if(pdir==NULL){
		printf("Can't open directory <%s>\n", dname);
		return -1;
	}

	/* get number of files in dircetory */
	ndir = 0;
	while((d=readdir(pdir))){
		ndir++;
	}
	d = malloc(sizeof(struct dirent)*ndir);

	/* read dirent first */
	rewinddir(pdir);
	for(i=0; i<ndir; i++){
		memcpy(&d[i], readdir(pdir), sizeof(struct dirent));
	}

	/* process each files */
	if(verbose)
		printf("Enter directory <%s> ...\n", dname);
	for(i=0; i<ndir; i++){
		if( d[i].d_name[0]=='.' &&( d[i].d_name[1] =='\0' || (d[i].d_name[1] == '.' && d[i].d_name[2] == '\0') ))
			continue;

		if(dname[0]=='.'){
			sprintf(fname, "%s", d[i].d_name);
		}else{
			sprintf(fname, "%s/%s", dname, d[i].d_name);
		}
		walk_dir(fname, func_ptr, verbose);
	}
	if(verbose)
		printf("Leave directory <%s> ...\n", dname);

	free(d);
	closedir(pdir);
	return 0;
}

/**************************************************************/

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
		//mkdir(name, 0777);
		mkdir(name);
		*p = '/';
		cp = p+1;
	};
}


/**************************************************************/




