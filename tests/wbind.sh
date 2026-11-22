#!/bin/sh
# wbind.py's host side: a guest with two -W bindings (/opt/wbind1, /opt/wbind2, the tools' and the
# catalog's shape), a -B one and a -b one, and the host renaming links when the guest asks.
#   sh wbind.sh BURROW ROOTFS RENAME [TMPDIR]     (on the device, as the app's user or root)
# Root mode: WBIND_ROOT=.../libkestrel_run.so [WBIND_RUN=DIR] as root: the guest starts with kestrel-run --root-stage.
# BURROW: the burrow binary; RENAME: tests/rename built for the device. Needs python3 in the rootfs.
[ $# -ge 3 ] || { echo "usage: wbind.sh BURROW ROOTFS RENAME [TMPDIR]"; exit 2; }
burrow=$1 rootfs=$2 rename=$3 t=${4:-${TMPDIR:-/data/local/tmp}/wbind.$$}
here=$(cd "$(dirname "$0")" && pwd)
rm -rf "$t"; mkdir -p "$t/w1/a/x/y/z" "$t/w1/b" "$t/w2/share" "$t/b1" "$t/rw" "$t/state" || exit 1
echo AAAA > "$t/w1/a/ORDER"; echo only-a > "$t/w1/a/only-a"; echo deep > "$t/w1/a/x/y/z/file"
echo BBBB > "$t/w1/b/ORDER"; echo SHARE > "$t/w2/share/ORDER"; echo bfile > "$t/b1/file"
ln -s a "$t/w1/current"
ln -s current "$t/w1/rel"
ln -s /opt/wbind2/share "$t/w1/abs"
ln -s /opt/wbind1/current "$t/w2/apps"
ln -s apps "$t/w2/chain"
ln -s /proc/self "$t/w2/procself"
ln -s /opt/wbind2/share "$t/b1/link"
chmod -R a+rX "$t"; chmod 777 "$t/rw"
# the host's part: "want-N" holds the new target of /opt/wbind1/current
( while [ ! -e "$t/rw/finished" ]; do
    for w in "$t"/rw/want-*; do
        [ -e "$w" ] || continue
        n=${w##*/want-}; read -r target < "$w"; rm -f "$w"
        rm -f "$t/w1/current.new"; ln -s "$target" "$t/w1/current.new" && "$rename" "$t/w1/current.new" "$t/w1/current"
        : > "$t/rw/done-$n"
    done
    sleep 0.05
done ) &
loop=$!
if [ -n "$WBIND_ROOT" ]; then
    # root mode (kestrel-run --root-stage, run as root by hand; WBIND_ROOT is libkestrel_run.so, WBIND_RUN a
    # run directory): the same folders as real read-only bind mounts, and the same wbind.py in the kernel's rules
    su -Z u:r:kestrel_guest:s0:c117,c257,c512,c768 -c "exec $WBIND_ROOT --root-stage --rootfs $rootfs --state $t/state --run ${WBIND_RUN:-$t/state} \
        --bind $t/rw:/wbind-rw --bind-ro-guest $t/w1:/opt/wbind1 --bind-ro-guest $t/w2:/opt/wbind2 --bind-ro $t/b1:/opt/wbind-b \
        --bind $here:/tmp/burrow-tests -- /usr/bin/env -i HOME=/root PATH=/usr/sbin:/usr/bin:/sbin:/bin KESTREL_BACKEND=root \
        python3 /tmp/burrow-tests/wbind.py" < /dev/null
else
    "$burrow" -r "$rootfs" -g "$t/state/pathgen" -b /dev -b /proc -b /sys \
        -b "$t/rw:/wbind-rw" -W "$t/w1:/opt/wbind1" -W "$t/w2:/opt/wbind2" -B "$t/b1:/opt/wbind-b" \
        -b "$here:/tmp/burrow-tests" -w /root -- \
        /usr/bin/env -i HOME=/root PATH=/usr/sbin:/usr/bin:/sbin:/bin python3 /tmp/burrow-tests/wbind.py
fi
rc=$?
: > "$t/rw/finished"; wait $loop 2>/dev/null
# the host's view: nothing below the read-only bindings changed
if [ "$(cat "$t/w1/a/ORDER")" = AAAA ] && [ "$(cat "$t/w1/b/ORDER")" = BBBB ] && [ ! -e "$t/w1/new" ] && [ ! -e "$t/w1/a/new" ]; then
    echo "ok   host: the files below the -W bindings are unchanged"
else
    echo "FAIL host: a file below a -W binding changed"; rc=1
fi
rm -rf "$t"
exit $rc
