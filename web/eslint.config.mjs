// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import tsParser from "@typescript-eslint/parser";

const hexColor = /^#[0-9a-f]{3,8}$/i;

/** Components use semantic tokens; raw colors cannot adapt to dark mode. */
const noHexColorLiterals = {
  meta: { type: "problem", messages: { hex: "Use a design token instead of a hex color literal." } },
  create(context) {
    return {
      Literal(node) {
        if (typeof node.value === "string" && hexColor.test(node.value)) context.report({ node, messageId: "hex" });
      },
    };
  },
};

export default [{
  files: ["**/*.{ts,tsx}"],
  ignores: ["**/generated/**", "**/node_modules/**"],
  languageOptions: { parser: tsParser, parserOptions: { ecmaVersion: "latest", sourceType: "module", ecmaFeatures: { jsx: true } } },
  plugins: { karst: { rules: { "no-hex-color-literals": noHexColorLiterals } } },
  rules: { "karst/no-hex-color-literals": "error" },
}];
