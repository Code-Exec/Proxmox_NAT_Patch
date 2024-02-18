#!/bin/bash
path=$2||'/usr/share/perl5/'
pvefw_ver=$3||`pveversion -v | grep pve-firewall`
patches_dir='patches/'
patch_path="$patches_dir/$pvefw_ver.diff"
file='Firewall.pm'

if [ "$1" == "run" ]; then
    if [ -e "$path$file.orig" ]; then
        echo "Allredy patched"
    else
        if [ -e "$patch_path" ]; then
            patch -b $path$file < "$patch_path"
            echo "Patch done"
        else
            echo -e "Patch for current version not found!
Please send mail to ssa.codex@gmail.com
or open a new issue on the github."
        fi
    fi
    
elif [ "$1" == "rollback" ]; then
    if [ -e "$path$file.orig" ]; then
        mv $path$file.orig $path$file
        echo "Rollback done"
    else
        echo "Backups not found"
    fi
else
    echo "Unknown command. Alowed - run, rollback"
fi

