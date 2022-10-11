module.exports = {
  // Override the base configuration to set the correct tsconfigRootDir.
  parserOptions: {
    tsconfigRootDir: __dirname,
  },

  rules: {
    'newline-per-chained-call': 'off',
    'no-useless-constructor': 'off',
    '@typescript-eslint/no-useless-constructor': 'error',
  },
};
