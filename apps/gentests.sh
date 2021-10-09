#!/bin/bash
# Created on: 28-Sep-2021, 05:08 pm EDT
# Added by:   mitthu (Aditya Basu)
# ----
# Use:
# - Generate test cases for name confusion.

BASE=tests

pushd () {
    command pushd "$@" > /dev/null
}

popd () {
    command popd "$@" > /dev/null
}

mkpush() {
    mkdir $1
    pushd $1
}

# Create workspace
rm -rf $BASE
mkdir $BASE
cd $BASE

# f01: silently lose files
mkpush f01
echo "bla" >name
echo "BLA" >NAME

cat >README <<EOF
    f01: silently lose files
    ---
    okay: prompt file being replaced
    fail: only one file exists w/o errors or prompt
EOF
popd

mkpush f01_patch
touch NAME
popd

# f02: bad perms on content
mkpush f02
echo "bla" >name
echo "BLA" >NAME; chmod 700 NAME

cat >README <<EOF
    f02: bad perms on content
    ---
    okay: If content=bla then perm=755. If content=BLA then perm=700.
    fail: content=bla has perms=700 OR content=BLA has perms=755
EOF
popd

mkpush f02_patch
touch NAME
popd

# f03: malformed name
mkpush f03
echo "bla" >name
echo "BLA" >NAME

cat >README <<EOF
    f03: malformed name
    ---
    okay: If name then contents="bla". If NAME then contents="BLA".
    fail: name contains "BLA"
EOF
popd

mkpush f03_patch
touch NAME
popd

# f04: write to pipe
mkpush f04
mkfifo namE
echo "bla" >NAME

cat >README <<EOF
    f04: write to pipe
    ---
    okay: just create file or the pipe
    fail: dump contents of NAME into namE|
EOF
popd

mkpush f04_patch
popd

# f05: regular hardlinks inconsistency
mkpush f05
echo "bla" >name
ln name Name
echo "BLA" >NAME

cat >README <<EOF
    f05: regular hardlinks inconsistency
    ---
    okay: don't support hardlinks
    fail: the result depends on order of input; examples:

        "tar -cvf NAME Name name"
        on untar, we get: Name 

        "tar -cvf Name NAME name"
        on untar, we get: NAME 
EOF
popd

mkpush f05_patch
touch Name NAME
popd

# f06: follow symlink
mkpush f06
mkdir -p dir
ln -s /tmp dir/baddir
mkdir -p DIR/baddir
touch DIR/baddir/never

cat >README <<EOF
    f06: follow symlink
    ---
    okay: don't support symlink
    fail: after untar etc., /tmp/never is created
EOF
popd

mkpush f06_patch
mkdir -p dir/baddir DIR/baddir
popd

# f07: hardlink to missing files
mkpush f07
mkdir -p dir
ln -s /tmp dir/baddir
mkdir -p DIR/baddir
ln dir/baddir DIR/baddir/never

cat >README <<EOF
    f07: hardlink to missing files
    ---
    okay: creating DIR/baddir/never fails
    fail: -
    notes:
        Originally dir/baddir is a symlink. However, it can be silently
        replaced with "DIR/baddir/". This results in hardlinking to a dir.
        which is prohibited.
EOF
popd

mkpush f07_patch
mkdir -p dir/baddir DIR/baddir
popd

###############
# Directories #
###############

# d01: silently merge directories
mkpush d01
mkdir dir DIR
echo "file1" >dir/file1
echo "file2" >DIR/file2

cat >README <<EOF
    d01: silently merge directories
    ---
    okay: dir has either file1 or file2
    fail: dir has both file1 and file2
EOF
popd

# d02: bad perms
mkpush d02
mkdir dir && chmod 777 dir
mkdir DIR && chmod 700 DIR
echo "file1" >dir/file1
echo "file2" >DIR/file2

cat >README <<EOF
    d02: bad perms
    ---
    okay: dir has perm=777 or DIR has perm=700
    fail: dir has perm=700 or DIR has perm=777
EOF
popd

# d03: follow symlink on conflict
mkpush d03
ln -s /tmp dir
mkdir DIR
echo "file2" >DIR/file2

cat >README <<EOF
    d02: bad perms
    ---
    okay: dir/ symlink is not followed
    fail: /tmp/file2 is created
EOF
popd
