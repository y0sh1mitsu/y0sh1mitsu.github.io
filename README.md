# y0sh1mitsu.github.io

Source of my blog, published at <https://y0sh1mitsu.github.io/>.

Built with [Astro](https://astro.build/) and deployed to GitHub Pages by
`.github/workflows/deploy.yml` on every push to `main`.

## Writing a post

Create a folder in `src/content/posts/` with an `index.md` and its images next to it
(`pnpm new-post my-post/index.md` scaffolds one). The folder name becomes the URL:
`src/content/posts/my-post/index.md` is served at `/posts/my-post/`.

```md
---
title: My post
published: 2026-01-31
description: One sentence shown in lists and link previews.
image: ./cover.jpg      # optional cover
tags: [DFIR]
category: Guide
draft: false            # true = hidden from the published site
---
```

Callouts are written `:::note` … `:::` (also `tip`, `important`, `warning`, `caution`).

## Commands

| Command        | Action                                   |
| -------------- | ---------------------------------------- |
| `pnpm install` | Install dependencies                     |
| `pnpm dev`     | Local preview at `http://localhost:4321` |
| `pnpm build`   | Build the site into `dist/`              |
| `pnpm check`   | Type-check the project                   |

Site name, intro text, navigation and social links live in `src/config.ts`;
colors and typography in `src/styles/global.css`; the About page in
`src/content/spec/about.md`.
