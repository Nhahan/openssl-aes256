webpack --config webpack.config.cjs &&
cp ./src/openssl-ha.node ./dist &&
mv ./dist/openssl-ha.d.ts ./dist/index.d.ts
