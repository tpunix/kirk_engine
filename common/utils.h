#ifndef UTILS_H
#define UTILS_H

#define MAX(a, b) (((a) > (b)) ? (a) : (b))
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#define NELEMS(a) (sizeof(a) / sizeof(a[0]))

void hex_dump(const char *str, void *addr, int size);


FILE *open_file(char *name, int *size);
u8 *load_file(char *name, int *size);
int write_file(char *file, void *buf, int size);

int walk_dir(char *dname, void *func_ptr, int verbose);
void mkdir_p(char *dname);

#endif

