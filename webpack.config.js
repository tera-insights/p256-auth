module.exports = {
  entry: './src/index.ts',
  output: {
    path: 'dist',
    filename: 'p256Auth.js',
    libraryTarget: "var",
    library: "p256Auth"
  },
  resolve: {
    extensions: ['.ts', '.js', '.tsx', '.jsx']
  },
  module: {
    loaders: [
      {
        test: /\.tsx?$/,
        exclude: /node_modules/,
        loader: 'ts-loader'
      },
      {
        test: /\.json$/,
        loader: "json-loader"
      }
    ]
  }
}