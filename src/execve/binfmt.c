/*
 * Author: Caten Hu
 * Date:   12/2/2023
 *
 * Description: Provide binfmt_misc
 * features for box86/box64 and wine
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "tracee/mem.h"
#include "syscall/chain.h"
#include "path/path.h"
#include "execve/aoxp.h"
#include "execve/execve.h"
#include "execve/binfmt.h"

int binfmt_max_magic_length = 0;

BinfmtEntry default_binfmt_entries[DEFAULT_BINFMT_ENTRIES_SIZE] = {{
    .name = "x86",
    .type = 'M',
    .offset = 0,
    .magic = "\x7f\x45\x4c\x46\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x03\x00", 
    .mask = "\xff\xff\xff\xff\xff\xff\xff\x00\xff\xff\xff\xff\xff\xff\xff\xff\xfe\xff\xff\xff", 
    .length = 20,
    .interpreter = "",
    .flags = ""
}, {
    .name = "x86_64",
    .type = 'M',
    .offset = 0,
    .magic = "\x7f\x45\x4c\x46\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x3e\x00",
    .mask = "\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\xff\xff\xff\xff\xff\xfe\xff\xff\xff",
    .length = 20,
    .interpreter = "",
    .flags = ""
}, {
    .name = "wine",
    .type = 'M',
    .offset = 0,
    .magic = "MZ",
    .mask = "\xff\xff", 
    .length = 2,
    .interpreter = "",
    .flags = ""
}};

int compare_magic(const char *data, const char *magic, const char *mask, size_t length) {
    for (size_t i = 0; i < length; ++i) {
        if ((data[i] & mask[i]) != (magic[i] & mask[i])) {
            return 0;
        }
    }
    return 1;
}

/**
 * @user_path is where the executable file is located in guest view (e.g. /home/tiny/hello_world).
 * @host_path is where the executable file is located in host view (e.g. /tmp/root/home/tiny/hello_world).
 * @user_path is the first argument of execve call. int execve(const char *pathname, char *const _Nullable argv[], char *const _Nullable envp[])
 * @user_path needs to be updated according to binfmt entries (e.g. -> /usr/bin/box64).
 * @host_path also needs to be updated (e.g. -> /tmp/root/usr/bin/box64).
 * I don't need to update SYSARG_1, which will be updated by translate_execve_enter(). 
 * For now, arguments in execve call should still be in guest view.
*/
int expand_binfmt_interpreter(Tracee *tracee, char host_path[PATH_MAX], char user_path[PATH_MAX]) {
    /* If wine is enabled as /usr/bin/wine64, a call to:
     *
     *     execve("./hello_world.exe", { "hello_world.exe", NULL }, ...)
     *
     * becomes:
     *
     *     execve("/usr/bin/wine64", { "/usr/bin/wine64", "./hello_world.exe", NULL }, ...)
     * 
     * since wine64 is a x64 file, if box64 is also enabled, it would become:
     * 
     *     execve("/usr/bin/box64", { "/usr/bin/box64", "/usr/bin/wine64", "./hello_world.exe", NULL }, ...)
     *  
     */
    for (size_t i = 0; i < DEFAULT_MAX_ITERATE_CHECK; i++) {
        int status;
	    int fd;
        int match_binfmt;
        char buffer[DEFAULT_FILE_BUFFER_LENGTH];
	    ArrayOfXPointers *argv;
        
        /* Inspect the executable.  */
        fd = open(host_path, O_RDONLY);
        if (fd < 0) 
            return 0;

        status = read(fd, buffer, binfmt_max_magic_length);
        if (status < binfmt_max_magic_length) {
            close(fd);
            return 0;
        }
        close(fd);

        match_binfmt = 0;

        for (size_t j = 0; j < DEFAULT_BINFMT_ENTRIES_SIZE; j++) {
            BinfmtEntry *entry = &default_binfmt_entries[j];

            if (entry->interpreter[0] == '\0' || !compare_magic(buffer, entry->magic, entry->mask, entry->length))
                continue;

            match_binfmt = 1;

            status = fetch_array_of_xpointers(tracee, &argv, SYSARG_2, 0);
            if (status < 0)
                return status;
            
            status = resize_array_of_xpointers(argv, 0, 1);
            if (status < 0)
                return status;

            status = write_xpointees(argv, 0, 2, entry->interpreter, user_path);
            if (status < 0)
                return status;
            
            status = push_array_of_xpointers(argv, SYSARG_2);
            if (status < 0)
                return status;

            strcpy(user_path, entry->interpreter);

            status = translate_path(tracee, host_path, AT_FDCWD, user_path, true);
            if (status < 0)
                return status;

            break;
        }

        if (!match_binfmt)
            break;

    }

    return 0;
}