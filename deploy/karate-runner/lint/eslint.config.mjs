// Used by the SCRS QA runner for a repository that has no ESLint flat config:
// ESLint's recommended rules for JavaScript and TypeScript, with Node and
// browser globals. A repository's own eslint.config.* always wins.
import js from "@eslint/js";
import globals from "globals";
import tseslint from "typescript-eslint";

export default [
  { ignores: ["**/node_modules/**", "**/dist/**", "**/build/**", "**/coverage/**", "**/vendor/**", "**/*.min.js"] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  { languageOptions: { globals: { ...globals.node, ...globals.browser } } },
];
