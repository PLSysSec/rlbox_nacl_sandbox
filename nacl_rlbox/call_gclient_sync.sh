#!/bin/bash
SCRIPT_DIR=$(dirname "$0")
cd $SCRIPT_DIR

if [ ! -d "./depot_tools" ]; then
  git clone --recursive https://chromium.googlesource.com/chromium/tools/depot_tools.git
fi

DEPOT_TOOLS_PATH=$(realpath ./depot_tools)
export PATH=$DEPOT_TOOLS_PATH:$PATH

if [ ! -d "./native_client" ]; then
    gclient sync
else
    echo "gclient sync has already run."
fi
