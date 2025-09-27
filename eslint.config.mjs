// @ts-check

import eslint from "@eslint/js"
import tseslint from "typescript-eslint"
import pluginImport from "eslint-plugin-import"

export default tseslint.config(
  eslint.configs.recommended,
  tseslint.configs.recommendedTypeChecked,

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
