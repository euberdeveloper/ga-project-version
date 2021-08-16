const path = require('path');
const webpack = require('webpack');

const libConfig = {
    target: 'node',
    mode: 'production',
    devtool: 'source-map',
    entry: {
        index: './src/index.ts'
    },
    resolve: {
        extensions: ['.ts', '.js']
    },
    module: {
        rules: [
            {
                test: /\.ts$/,
                include: path.resolve(__dirname, 'src'),
                use: [
                    {
                        loader: 'ts-loader'
                    }
                ]
            }
        ]
    },
    plugins: [
        new webpack.EnvironmentPlugin(['IS_WEBPACK'])
    ],
    output: {
        path: path.resolve(__dirname, 'bundled'),
        filename: 'index.js',
        umdNamedDefine: true,
    }
};


module.exports = [
    libConfig
];
