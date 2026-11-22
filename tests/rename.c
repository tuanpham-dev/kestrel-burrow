/* rename(2) of the first path over the second, as the host side of wbind.sh needs it: toybox's `mv -T`
 * refuses a symlink over a symlink to a directory. cc -static -o rename rename.c */
#include <stdio.h>
int main(int argc, char** argv) {
    if (argc != 3) return 2;
    if (rename(argv[1], argv[2])) { perror("rename"); return 1; }
    return 0;
}
