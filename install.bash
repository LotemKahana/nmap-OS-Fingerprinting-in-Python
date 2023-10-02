#!/bin/bash

# check if pyinstaller exists
if ! [[ $(which pyinstaller) ]]; then
    echo "could not find pyinstaller"
    echo "do you want to install pyinstaller? y/n"
    read install

    if [ "$install" == "y" ]; then
        pip install pyinstaller
    else
        echo "please install pyinstaller and try again."
        set -e
    fi
fi

echo "found pyinstaller at $(which python3 | head -n 1)"
# compile using pyinstaller
pyinstaller main.spec
if [ $? -eq 0 ]; then
    echo "Pyinstaller finished"
else
    echo "Pyinstaller failed, aborting."
    set -e
fi

# copy dependencies
cp -r external_files ./dist

echo "finished copping files."
echo "make sure you keep all files in \"dist\" folder together."
./dist/os_detect --help
