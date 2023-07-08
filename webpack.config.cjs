const path = require('path');

module.exports = {
    mode: 'production',
    entry: {
        index: './src/openssl-ha.ts',
    },
    output: {
        path: path.resolve(__dirname, 'dist'),
        filename: 'index.js',
        clean: true,
        library: {
            name: 'openssl-ha',
            type: 'umd',
        },
        globalObject: 'this',
    },
    resolve: {
        extensions: ['.ts', '.js', '.node'],
    },
    module: {
        rules: [
            {
                test: /\.ts$/,
                use: ['babel-loader', 'ts-loader'],
                exclude: /node_modules/,
            },
            {
                test: /\.node$/,
                use: 'ignore-loader',
            },
        ],
    },
    target: 'node',
};
