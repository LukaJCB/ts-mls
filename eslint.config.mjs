// @ts-check

import eslint from "@eslint/js"
import { defineConfig } from "eslint/config"
import tseslint from "typescript-eslint"
import pluginImport from "eslint-plugin-import"
import noObjectComparison from "eslint-plugin-no-object-comparison"

export default defineConfig(
  eslint.configs.recommended,
  tseslint.configs.recommendedTypeChecked,
  noObjectComparison.configs.recommended,

  {
    languageOptions: {
      parserOptions: {
        project: "./tsconfig.json",
      },
    },
    plugins: {
      import: pluginImport,
    },
    rules: {
      "@typescript-eslint/no-unused-vars": "off",
      "@typescript-eslint/require-await": "off",
      "@typescript-eslint/restrict-template-expressions": "off",
      "import/extensions": [
        "error",
        "ignorePackages",
        {
          js: "always",
          ts: "never",
        },
      ],
    },
  },
)
