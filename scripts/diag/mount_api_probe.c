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

// Diagnostic only: calls the two libfuse2 mount functions directly, the way
// fuser does (fuse_mount_compat25, returns a raw fd) and the normal 2.6 API
// (fuse_mount, returns a channel). Prints which one gives a usable fd.
// Usage: mount_api_probe <compat25|mount> <mountpoint> [-o opts]

#define FUSE_USE_VERSION 26

#include <errno.h>
#include <fuse.h>
#include <fuse_lowlevel.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <unistd.h>

int fuse_mount_compat25(const char *mountpoint, struct fuse_args *args);

int main(int argc, char *argv[])
{
    if (argc < 3) {
        fprintf(stderr, "usage: %s <compat25|mount> <mountpoint> [-o opts]\n", argv[0]);
        return 2;
    }
    const char *mode = argv[1];
    const char *mp = argv[2];
    // Same argument shape as fuser: program name, then "-o" "opt" pairs.
    char *fargv[8] = {"rust-fuse", NULL};
    int fargc = 1;
    for (int i = 3; i < argc && fargc < 7; i++) {
        fargv[fargc++] = argv[i];
    }
    struct fuse_args args = FUSE_ARGS_INIT(fargc, fargv);

    int fd = -1;
    errno = 0;
    if (strcmp(mode, "compat25") == 0) {
        fd = fuse_mount_compat25(mp, &args);
    } else {
        struct fuse_chan *ch = fuse_mount(mp, &args);
        if (ch != NULL) {
            fd = fuse_chan_fd(ch);
        }
    }
    int err = errno;
    printf("%s: fd=%d errno=%d (%s)\n", mode, fd, err, strerror(err));
    if (fd >= 0) {
        sleep(1);
        unmount(mp, 0);
    }
    return fd >= 0 ? 0 : 1;
}
