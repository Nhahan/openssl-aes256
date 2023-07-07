#!/bin/bash

current_dir=$(pwd)

cd ./native

export LIBRARY_PATH=$LIBRARY_PATH:/opt/homebrew/opt/openssl@3/lib

node-gyp configure
node-gyp build

cp ./build/Release/openssl-ha.node $current_dir/src/openssl-ha.node

cd $current_dir