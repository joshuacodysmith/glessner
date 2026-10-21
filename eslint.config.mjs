// ESLint for the page's ES modules. scripts/lint.py runs it, with ruff for the Python.
import { defineConfig } from "eslint/config";
import { builtinRules } from "eslint/use-at-your-own-risk";

// ESLint's recommended rules, read from the installed ESLint: the set @eslint/js lists, without another package.
const recommended = Object.fromEntries(
  [...builtinRules].filter(([, rule]) => rule.meta?.docs?.recommended).map(([name]) => [name, "error"]),
);

// The browser globals the page uses. A module that starts using another one fails no-undef until it's added here.
const browser = Object.fromEntries(
  [
    "AbortController", "CSS", "Event", "Node", "NodeFilter", "ResizeObserver", "URLSearchParams", "clearInterval", "clearTimeout", "document", "fetch",
    "getComputedStyle", "localStorage", "location", "navigator", "performance", "requestAnimationFrame", "sessionStorage",
    "setInterval", "setTimeout", "structuredClone", "window",
  ].map((name) => [name, "readonly"]),
);

export default defineConfig([
  {
    files: ["src/glessner/static/js/**/*.js"],
    languageOptions: { ecmaVersion: "latest", sourceType: "module", globals: browser },
    linterOptions: { reportUnusedDisableDirectives: "error" },
    rules: {
      ...recommended,
      // The code names an ignored error `_`, as in `catch (_)`.
      "no-unused-vars": ["error", { caughtErrorsIgnorePattern: "^_" }],
    },
  },
]);
