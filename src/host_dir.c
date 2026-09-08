/* Host directory reading shim. The 3B1 reads directories with plain read(2),
 * getting 16-byte `struct direct` records (2-byte big-endian inode + 14-byte
 * name). Linux/macOS forbid read() on directories, so we open the directory
 * with opendir() and hand entries back one at a time.
 *
 * We keep a small table of open DIR* keyed by an integer handle so the Zig
 * side can reference them without knowing the platform DIR layout. */

#include <dirent.h>
#include <string.h>
#include <stddef.h>

#define UPC_MAXDIR 64
static DIR *upc_dirs[UPC_MAXDIR];

/* Open a directory; returns a handle >= 0 or -1. */
int upc_diropen(const char *path) {
    for (int i = 0; i < UPC_MAXDIR; i++) {
        if (upc_dirs[i] == NULL) {
            DIR *d = opendir(path);
            if (!d) return -1;
            upc_dirs[i] = d;
            return i;
        }
    }
    return -1;
}

/* Read the next entry. Writes up to 14 name bytes into name_out (NUL-padded)
 * and the inode into *ino_out. Returns 1 if an entry was read, 0 at end, -1 on
 * a bad handle. */
int upc_dirread(int handle, unsigned long *ino_out, char *name_out) {
    if (handle < 0 || handle >= UPC_MAXDIR || upc_dirs[handle] == NULL) return -1;
    struct dirent *e = readdir(upc_dirs[handle]);
    if (!e) return 0;
    *ino_out = (unsigned long)e->d_ino;
    memset(name_out, 0, 14);
    strncpy(name_out, e->d_name, 14);
    return 1;
}

void upc_dirclose(int handle) {
    if (handle >= 0 && handle < UPC_MAXDIR && upc_dirs[handle]) {
        closedir(upc_dirs[handle]);
        upc_dirs[handle] = NULL;
    }
}
