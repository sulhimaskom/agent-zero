// Agent Zero - ESLint Configuration
// Lenient config for initial linting setup - warnings only, not errors
// This allows incremental fixes without breaking the build

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
      // Possible Errors - use warnings to not break build
      'no-console': 'off',
      'no-debugger': 'warn',
      'no-unused-vars': ['warn', { argsIgnorePattern: '^_' }],
      'no-undef': 'warn',

      // Best Practices - warnings
      'eqeqeq': 'warn',
      'no-var': 'warn',
      'prefer-const': 'warn',
      'no-implicit-globals': 'warn',

      // Style - warnings for gradual adoption
      'semi': 'warn',
      'quotes': 'warn',
      'indent': 'warn',
      'comma-dangle': 'warn',
      'no-trailing-spaces': 'warn',
      'eol-last': 'warn',

      // ES6+ - warnings
      'no-duplicate-imports': 'warn',
      'no-useless-rename': 'warn',
      'object-shorthand': 'warn',
      'prefer-arrow-callback': 'warn',
      'prefer-template': 'warn',

      // Best practices - errors (these are important)
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
      'eqeqeq': 'warn',
      'no-var': 'warn',
      'prefer-const': 'warn',
      'semi': 'warn',
      'quotes': 'warn',
      'indent': 'warn',
      'comma-dangle': 'warn',
      'no-trailing-spaces': 'warn',
      'eol-last': 'warn',
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
      'no-unused-vars': 'off',
    },
  },
]);
