#!/bin/bash
path=$2||'/usr/share/perl5/'
file='Firewall.pm'

if [ "$1" == "run" ]; then
    if [ -e "$path$file.orig" ]; then
        echo "Allredy patched"
    else
        patch -b $path$file < diff.txt
        echo "Patch done"
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

