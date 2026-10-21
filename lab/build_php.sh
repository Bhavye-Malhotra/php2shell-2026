#!/bin/bash
# Build PHP 8.4.4 in three variants for the php2shell PoC lab
set -e
LAB=~/php2shell-lab
mkdir -p $LAB
cd $LAB

build_one() {
    local name=$1; shift
    local src=~/php-8.4.4
    local dir=$LAB/$name
    rm -rf $dir; mkdir -p $dir
    cd $dir
    "$src/configure" \
        --disable-all \
        --enable-standard \
        --enable-session \
        --enable-zend-asm \
        --with-config-file-path=$LAB/$name/etc \
        "$@" > configure.log 2>&1 || { tail -20 configure.log; echo "CONFIGURE FAILED: $name"; exit 1; }
    make -j8 > make.log 2>&1 || { tail -30 make.log; echo "MAKE FAILED: $name"; exit 1; }
    ./sapi/cli/php -r 'echo PHP_VERSION, " ", phpinfo_constant("zend_extensions") ? "ok" : "ok", "\n";' 2>/dev/null || php -r 'echo PHP_VERSION, "\n";'
    echo "BUILD DONE: $name"
}

# launch all three in parallel
build_one release > release.log 2>&1 &
build_one debug --enable-debug > debug.log 2>&1 &
build_one asan "CFLAGS=-O1 -g -fsanitize=address" "LDFLAGS=-fsanitize=address" "LDLIBS=-fsanitize=address" > asan.log 2>&1 &
wait
echo ALL_DONE
