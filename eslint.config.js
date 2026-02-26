// Agent Zero - ESLint Configuration
// Flat config format (ESLint v9+)

import { defineConfig } from 'eslint/config';
import globals from 'globals';

export default defineConfig([
  {
    name: 'agent-zero/webui-sources',
    files: ['webui/js/**/*.js', 'webui/components/**/*.js'],
    ignores: [
      '**/*.min.js',
      '**/vendor/**',
      '**/transformers@3.0.2.js',
    ],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'module',
      globals: {
        ...globals.browser,
        ...globals.es2022,
      },
    },
    rules: {
      // Possible Errors
      'no-console': 'off', // Console logging is used for debugging
      'no-debugger': 'warn',
      'no-unused-vars': ['warn', { argsIgnorePattern: '^_' }],
      'no-undef': 'warn',

      // Best Practices
      'eqeqeq': ['error', 'smart'],
      'no-var': 'error',
      'prefer-const': 'warn',
      'no-implicit-globals': 'warn',

      // Style
      'semi': ['error', 'always'],
      'quotes': ['error', 'single', { avoidEscape: true }],
      'indent': ['error', 2],
      'comma-dangle': ['error', 'always-multiline'],
      'no-trailing-spaces': 'error',
      'eol-last': ['error', 'always'],

      // ES6+
      'no-duplicate-imports': 'error',
      'no-useless-rename': 'error',
      'object-shorthand': 'warn',
      'prefer-arrow-callback': 'warn',
      'prefer-template': 'warn',

      // Best practices - error prevention
      'no-eval': 'error',
      'no-implied-eval': 'error',
      'no-new-func': 'error',
      'no-script-url': 'error',
    },
  },
  {
    name: 'agent-zero/webui-root',
    files: ['webui/*.js'],
    ignores: ['**/*.min.js'],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'module',
      globals: {
        ...globals.browser,
        ...globals.es2022,
      },
    },
    rules: {
      'no-console': 'off',
      'no-debugger': 'warn',
      'no-unused-vars': ['warn', { argsIgnorePattern: '^_' }],
      'no-undef': 'warn',
      'eqeqeq': ['error', 'smart'],
      'no-var': 'error',
      'prefer-const': 'warn',
      'semi': ['error', 'always'],
      'quotes': ['error', 'single', { avoidEscape: true }],
      'indent': ['error', 2],
      'comma-dangle': ['error', 'always-multiline'],
      'no-trailing-spaces': 'error',
      'eol-last': ['error', 'always'],
      'no-eval': 'error',
      'no-implied-eval': 'error',
      'no-new-func': 'error',
      'no-script-url': 'error',
    },
  },
  {
    name: 'agent-zero/service-worker',
    files: ['webui/js/sw.js'],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'script',
      globals: {
        ...globals.serviceworker,
      },
    },
    rules: {
      'no-unused-vars': 'off', // Service workers have specific lifecycle
    },
  },
]);
