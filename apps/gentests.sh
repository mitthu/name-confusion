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
    d03: follow symlink on conflict
    ---
    okay: dir/ symlink is not followed
    fail: /tmp/file2 is created
EOF
popd

####################
# All Combinations #
####################

# a1.1 file - file
mkpush a1.1
echo "bla" >name && chmod 700 name
echo "BLA" >NAME && chmod 777 NAME

cat >README <<EOF
    a1.1: file - file
    ---
    okay: prompt file being replaced
    fail:
        1) only one file exists w/o errors or prompt
        2) incorrect filename-content pair (look at case of filename)
        3) incorrect filename-perm pair
EOF
popd

# a1.2 file (old) - empty directory (new)
mkpush a1.2
mkdir a b

echo "bla" >a/name && chmod 700 a/name
mkdir a/NAME

# for rsync (flipped case)
echo "BLA" >b/NAME && chmod 700 b/NAME
mkdir b/name

cat >README <<EOF
    a1.2: file - empty directory
    ---
    okay: error OR lose empty directories
    fail:
        1) no error
EOF
popd


# a1.3 file (old) - directory w/ file (new)
mkpush a1.3
mkdir a b

echo "bla" >a/name && chmod 700 a/name
mkdir a/NAME
touch a/NAME/file1

# for rsync (flipped case)
echo "BLA" >b/NAME && chmod 700 b/NAME
mkdir b/name
touch b/name/file2

cat >README <<EOF
    a1.3: file - directory w/ contents
    ---
    okay: error
    fail:
        1) Silently lose entire sub-directory
        2) No error reported
EOF
popd

# a3.1 symlink to file - file
mkpush a3.1

# create symlinked files
rm -f /tmp/{sfile1,sfile2}
echo "file1" >/tmp/sfile1
echo "file2" >/tmp/sfile2
chmod 777 /tmp/{sfile1,sfile2}

echo "bla" >name1 && chmod 700 name1
ln -s /tmp/sfile1 NAME1

# for rsync (flipped case)
ln -s /tmp/sfile2 name2
echo "BLA" >NAME2 && chmod 700 NAME2

cat >README <<EOF
    a3.1: symlink to file - file
    ---
    okay:
        symlink replaced by file
        /tmp/{sfile1,sfile2} are empty
    fail:
        write new file to symlinked file
        /tmp/{sfile1,sfile2} not empty
        filename-filetype mismatch
        filename-perm. mismatch
        empty content
EOF
popd

# a5.1 hardlink - file
mkpush a5.1

# create hardlinked file
echo "hfileout" >../hfileout # (outside archive)
echo "hfilein" >hfilein
chmod 777 ../hfileout hfilein
ln hfilein hcontrol

# HL outside archive
echo "name1" >name1 && chmod 700 name1
ln ../hfileout NAME1

# for rsync (flipped case)
ln ../hfileout name2
echo "NAME2" >NAME2 && chmod 700 NAME2

# HL inside archive
echo "name3" >name3 && chmod 700 name3
ln hfilein NAME3

# for rsync (flipped case)
ln hfilein name4
echo "NAME4" >NAME4 && chmod 700 NAME4

cat >README <<EOF
    a5.1: hardlink - file
    ---
    okay:
        hardlink is honored
            i(NAME3) = i(hfilein)
            i(hcontrol) = i(hfilein)
        content
            NAME1 = hfileout (perms=777)
            NAME3 = hfilein (perms=777)
            Others, name=content & perms=777
    fail:
        ../hfilein or hfileout content is changed
        filename-content mismatch
        filename-perm. mismatch
        empty content
EOF
popd

# a5.5 hardlink - hardlink
# Cases
#   NC bet. hardlinks of eachother (cyclic)
#   NC bet. hardlink to different targets
mkpush a5.5

# Cyclic
echo "one" >name1
ln name1 NAME1

# (flipped case)
echo "two" >NAME2
ln NAME2 name2

# Different targets
echo "name3 / hfile1" >hfile1
echo "NAME3 / hfile2" >hfile2
ln hfile1 name3
ln hfile2 NAME3

cat >README <<EOF
    a5.5: hardlink - hardlink
    ---
    okay:
        hardlink is honored
        content
            name1/NAME1 contains "one"
            name2/NAME2 contains "two"
            name3 = "name3 / hfile1"
            NAME3 = "NAME3 / hfile2"
    fail:
        filename-content mismatch
        empty content
EOF
popd

# a6.1 pipe - file
mkpush a6.1

echo "bla" >name1 && chmod 700 name1
mkfifo NAME1      && chmod 777 NAME1

# for rsync (flipped case)
mkfifo name2      && chmod 777 name2
echo "BLA" >NAME2 && chmod 700 NAME2


cat >README <<EOF
    a6.1: pipe - file
    ---
    okay:
        pipe replaced by file
        pipe perms=777
    fail:
        dump file contents to pipe
EOF
popd
