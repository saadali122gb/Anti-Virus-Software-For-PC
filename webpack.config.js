const path = require('path');

module.exports = {
    mode: 'development',
    target: 'electron-renderer',
    entry: './src/ui/renderer.js',
    output: {
        path: path.resolve(__dirname, 'src/ui'),
        filename: 'bundle.js'
    },
    module: {
        rules: [
            {
                test: /\.jsx?$/,
                exclude: /node_modules/,
                use: {
                    loader: 'babel-loader',
                    options: {
                        presets: ['@babel/preset-react']
                    }
                }
            },
            {
                test: /\.css$/,
                use: ['style-loader', 'css-loader']
            }
        ]
    },
    resolve: {
        extensions: ['.js', '.jsx']
    },
    devtool: 'source-map'
};
