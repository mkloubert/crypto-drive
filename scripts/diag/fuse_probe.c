// crypto-drive
// Copyright (C) 2026  Marcel Joachim Kloubert
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

// Diagnostic only: the smallest possible FUSE file system (an empty root
// directory). Build with -DPROBE_FUSE=2 against libfuse2 or -DPROBE_FUSE=3
// against libfuse3. Used by scripts/diag/fuse-probe.sh to check whether
// macFUSE can mount at all, independent of crypto-drive and fuser.

#if PROBE_FUSE == 3
#define FUSE_USE_VERSION 31
#else
#define FUSE_USE_VERSION 26
#endif

#include <errno.h>
#include <fuse.h>
#include <string.h>
#include <sys/stat.h>

#if PROBE_FUSE == 3
static int probe_getattr(const char *path, struct stat *st, struct fuse_file_info *fi)
#else
static int probe_getattr(const char *path, struct stat *st)
#endif
{
#if PROBE_FUSE == 3
    (void)fi;
#endif
    memset(st, 0, sizeof *st);
    if (strcmp(path, "/") == 0) {
        st->st_mode = S_IFDIR | 0755;
        st->st_nlink = 2;
        return 0;
    }
    return -ENOENT;
}

static struct fuse_operations probe_ops = {
    .getattr = probe_getattr,
};

int main(int argc, char *argv[])
{
    return fuse_main(argc, argv, &probe_ops, NULL);
}
