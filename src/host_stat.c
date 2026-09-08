/* Host stat shims: fill a fixed-layout struct (matching Zig's HostStat) from
 * the platform's stat(2)/fstat(2), so the Zig side doesn't depend on the
 * host's struct stat layout. */

#include <sys/stat.h>
#include <sys/types.h>

struct upc_host_stat {
    unsigned int  mode;
    unsigned int  nlink;
    unsigned int  uid;
    unsigned int  gid;
    long long     size;
    long long     atime;
    long long     mtime;
    long long     ctime;
    unsigned long long dev;
    unsigned long long ino;
    unsigned long long rdev;
};

static void fill(struct upc_host_stat *o, const struct stat *s) {
    o->mode  = (unsigned int)s->st_mode;
    o->nlink = (unsigned int)s->st_nlink;
    o->uid   = (unsigned int)s->st_uid;
    o->gid   = (unsigned int)s->st_gid;
    o->size  = (long long)s->st_size;
    o->atime = (long long)s->st_atime;
    o->mtime = (long long)s->st_mtime;
    o->ctime = (long long)s->st_ctime;
    o->dev   = (unsigned long long)s->st_dev;
    o->ino   = (unsigned long long)s->st_ino;
    o->rdev  = (unsigned long long)s->st_rdev;
}

int upc_host_stat(const char *path, struct upc_host_stat *out) {
    struct stat s;
    int r = stat(path, &s);
    if (r == 0) fill(out, &s);
    return r;
}

int upc_host_fstat(int fd, struct upc_host_stat *out) {
    struct stat s;
    int r = fstat(fd, &s);
    if (r == 0) fill(out, &s);
    return r;
}

#include <errno.h>

/* Portable errno accessor. glibc uses __errno_location, macOS __error,
 * Windows _errno — <errno.h>'s `errno` macro expands to the right one. */
int upc_errno(void) {
    return errno;
}
