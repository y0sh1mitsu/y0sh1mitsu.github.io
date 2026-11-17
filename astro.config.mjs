import sitemap from "@astrojs/sitemap";
import { defineConfig } from "astro/config";
import remarkDirective from "remark-directive";
import { rehypeShiftHeadings } from "./src/plugins/rehype-shift-headings.mjs";
import { rehypeTableWrap } from "./src/plugins/rehype-table-wrap.mjs";
import { remarkAdmonitions } from "./src/plugins/remark-admonitions.mjs";

// https://astro.build/config
export default defineConfig({
	site: "https://y0sh1mitsu.github.io/",
	base: "/",
	trailingSlash: "always",
	integrations: [sitemap()],
	markdown: {
		remarkPlugins: [remarkDirective, remarkAdmonitions],
		rehypePlugins: [rehypeShiftHeadings, rehypeTableWrap],
		shikiConfig: {
			themes: { light: "github-light", dark: "github-dark-dimmed" },
			defaultColor: false,
			wrap: false,
		},
	},
});
