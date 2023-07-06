#!/bin/bash

current_dir=$(pwd)

cd ./native

export LIBRARY_PATH=$LIBRARY_PATH:/opt/homebrew/opt/openssl@3/lib

node-gyp configure
node-gyp build

cp ./build/Release/aes256.node $current_dir/src/aes256.node

cd $current_dir