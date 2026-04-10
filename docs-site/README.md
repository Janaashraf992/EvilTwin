# EvilTwin Docusaurus Site

This directory contains the Docusaurus website for EvilTwin documentation.

## Canonical Source of Truth

- Canonical documentation source: `/docs-site/docs`.
- The site shell, navigation, and technical docs are maintained together in this folder.
- Do not maintain duplicate technical docs in another top-level docs tree.

## Local Development

```bash
cd docs-site
npm install
npm start
```

## Production Build

```bash
cd docs-site
npm run build
npm run serve
```

## Structure

- `docusaurus.config.js`: Site configuration
- `sidebars.js`: Sidebar hierarchy
- `docs/`: Rendered documentation pages (canonical source)
- `src/pages/index.js`: Landing page
- `src/css/custom.css`: Theme customizations

## Notes

- Mermaid diagrams are enabled globally via `@docusaurus/theme-mermaid`.
- Docs route base path is `/docs`.
