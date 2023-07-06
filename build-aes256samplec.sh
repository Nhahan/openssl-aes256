#!/bin/bash

current_dir=$(pwd)

cd ./native

export LIBRARY_PATH=$LIBRARY_PATH:/opt/homebrew/opt/openssl@3/lib

node-gyp configure
node-gyp build

cp ./build/Release/hs256.node $current_dir/src/hs256.node

cd $current_dir