module.exports = {
  entry: './src/index.ts',
  output: {
    filename: 'dist/index.js',
    libraryTarget: "var",
    library: "p256-auth"
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