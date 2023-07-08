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
                use: ['ts-loader'],
                exclude: /node_modules/,
            },
            {
                test: /\.node$/,
                use: 'ignore-loader',
            },
        ],
    },
    externals: {
        './openssl-ha.node': 'commonjs ./openssl-ha.node',
    },
    target: 'node',
};
