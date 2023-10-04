#!/bin/bash

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Default installation directory
INSTALL_DIR="./dist"

# Parse command-line arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        -d|--dir)
            INSTALL_DIR="$2"
            shift 2
            ;;
        *)
            echo "Usage: $0 [-d|--dir <installation_directory>]"
            exit 1
            ;;
    esac
done

# Check if the chosen directory exists and create it if necessary
if [ ! -d "$INSTALL_DIR" ]; then
    echo "Creating directory: $INSTALL_DIR"
    mkdir -p "$INSTALL_DIR"
fi

# Check if python is installed and meets the version requirement
if ! command_exists python3; then
    if ! command_exists python; then
        echo "Could not find Python"
        echo "Please install Python version 3.9+ and resume"
        exit 1
    else
        alias python3=python
    fi
fi

if python3 -c 'import sys; sys.exit(not (sys.version_info[0] == 3 and sys.version_info[1] >= 9))'; then
    echo "Found Python version $(python3 --version)"
else
    echo "Invalid Python version $(python3 --version)"
    echo "Please install version 3.9+ and resume"
    exit 1
fi

# Check if pyinstaller exists and install if necessary
if ! command_exists pyinstaller; then
    echo "Could not find PyInstaller"
    read -p "Do you want to install PyInstaller? (y/n): " install

    if [ "$install" == "y" ]; then
        pip install pyinstaller
    else
        echo "Please install PyInstaller and try again."
        exit 1
    fi
fi

echo "Found PyInstaller at $(which pyinstaller | head -n 1)"

# Compile using pyinstaller
# Specify the output directory for PyInstaller using --distpath
pyinstaller --distpath "$INSTALL_DIR" main.spec

if [ $? -eq 0 ]; then
    echo "PyInstaller finished"
else
    echo "PyInstaller failed, aborting."
    exit 1
fi

# Copy dependencies to the installation directory
cp -r external_files "$INSTALL_DIR"

echo "Finished copying files."
echo "The application is installed in: $INSTALL_DIR"

echo "Finished copying files."
echo "Make sure you keep all files in the \"dist\" folder together."
./dist/os_detect --help