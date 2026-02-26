import js from '@eslint/js';
import globals from 'globals';

/**
 * ESLint configuration for Agent Zero WebUI
 * Uses ESLint flat config format (ESLint 9+)
 */
export default [
  // Base recommended rules
  js.configs.recommended,

  // Browser globals
  {
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'module',
      globals: {
        ...globals.browser,
        ...globals.es2021,
        // Alpine.js specific globals
        Alpine: 'readonly',
        // Custom global functions
        openModal: 'readonly',
        closeModal: 'readonly',
        displayInfo: 'readonly',
        loadComponents: 'readonly',
      },
    },
  },

  {
    ignores: [
      'vendor/**',
      '**/*.min.js',
      '**/*.min.css',
      'index.min.js',
      'index.min.css',
      'login.min.css',
      'components/_examples/**',
      'js/transformers@3.0.2.js',
      'js/transformers@3.0.2.min.js',
      'components/welcome/welcome-store.js',
    ],
  },
  {
    ignores: [
      'vendor/**',
      '**/*.min.js',
      '**/*.min.css',
      'index.min.js',
      'index.min.css',
      'login.min.css',
      'components/_examples/**',
      'js/transformers@3.0.2.js',
      'js/transformers@3.0.2.min.js',
    ],
  },

  // Custom rules for webui
  {
    rules: {
      // Disable all base rules that are too strict for legacy code
      'no-empty': 'off',
      'no-cond-assign': 'off',
      'no-dupe-keys': 'off',
      'no-fallthrough': 'off',
      'no-unused-vars': 'off',
      'no-undef': 'off',
      'no-useless-escape': 'off',
      'no-control-regex': 'off',
      'getter-return': 'off',
      'no-async-promise-executor': 'off',
      'no-import-assign': 'off',
      'no-setter-return': 'off',

      // ES6+ rules - be lenient
      'no-unused-vars': ['warn', {
        argsIgnorePattern: '^_',
        varsIgnorePattern: '^_',
      }],
      'no-undef': ['warn'],

      // Best practices
      'no-alert': 'warn',
      'no-console': 'off', // Allow console for debugging
      'no-debugger': 'warn',

      // Style rules - downgraded to warnings for gradual adoption
      'semi': ['warn', 'always'],
      'quotes': ['warn', 'single', { avoidEscape: true }],
      'indent': ['warn', 2],
      'comma-dangle': ['warn', 'always-multiline'],
      'no-multiple-empty-lines': ['warn', { max: 2 }],
      'eol-last': ['warn', 'always'],

      // Modern JS patterns
      'prefer-const': 'warn',
      'no-var': 'warn',

      // Disable some overly strict rules
      'no-prototype-builtins': 'off',
      'no-case-declarations': 'off',
    },
  },
];
