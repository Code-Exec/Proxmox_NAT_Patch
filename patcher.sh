#!/bin/bash
#we can use this path from params
if [$2 eq ""]; then
    path='/usr/share/perl5/PVE/Firewall.pm'
else
    path=$2
fi

#we can use this path from params
if [$3 eq ""]; then
    pvefw_ver=`pveversion -v | grep pve-firewall`
else
    pvefw_ver=$3
fi

#checking that is all tools are exists
if [ ! -x "$(command -v patch)" ];
then
    echo "<patch> could not be found. Please install it 'apt install patch'"
    exit 1
fi

execute_path=$( dirname "$0" )
patches_dir="$execute_path/patches"
patch_path="$patches_dir/$pvefw_ver.diff"

if [ "$1" == "run" ]; then
    if [ -e "$path.orig" ]; then
        echo "Allredy patched"
    else
        if [ -e "$patch_path" ]; then
            cp $path $path.orig
            patch -b $path < "$patch_path"
            echo "Patching done"
        else
            echo -e "Patch for version '${pvefw_ver}' not found!
Please send mail to ssa.codex@gmail.com
or open a new issue on the github."
        fi
    fi
    
elif [ "$1" == "rollback" ]; then
    if [ -e "$path.orig" ]; then
        mv $path.orig $path
        echo "Rollback done"
    else
        echo "Backups not found"
    fi
else
    echo "Unknown command. Alowed - run, rollback"
fi

