#include <stdlib.h>

#define DEFAULT_BINFMT_ELEMENT_MAX_LENGTH 256
#define DEFAULT_FILE_BUFFER_LENGTH 4096
#define DEFAULT_MAX_ITERATE_CHECK 3
#define DEFAULT_BINFMT_ENTRIES_SIZE 3

typedef struct {
    char name[DEFAULT_BINFMT_ELEMENT_MAX_LENGTH]; // ignored
    char type; // ignored
    int offset; // ignored!!!
    char magic[DEFAULT_BINFMT_ELEMENT_MAX_LENGTH];
    char mask[DEFAULT_BINFMT_ELEMENT_MAX_LENGTH];
    size_t length; // size of magic or mask. The size of magic and mask must be the same
    char interpreter[PATH_MAX]; // empty if not set
    char flags[DEFAULT_BINFMT_ELEMENT_MAX_LENGTH]; // ignored
} BinfmtEntry;

extern int binfmt_max_magic_length;
extern BinfmtEntry default_binfmt_entries[];