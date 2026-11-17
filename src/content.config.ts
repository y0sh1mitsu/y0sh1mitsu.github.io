import { defineCollection, z } from "astro:content";
import { glob } from "astro/loaders";

const posts = defineCollection({
	loader: glob({ pattern: "**/*.{md,mdx}", base: "./src/content/posts" }),
	schema: ({ image }) =>
		z.object({
			title: z.string(),
			published: z.coerce.date(),
			updated: z.coerce.date().optional(),
			draft: z.boolean().optional().default(false),
			description: z.string().optional().default(""),
			// Cover image, relative to the post (e.g. "./cover.jpg"). Optional.
			image: z.preprocess((v) => (v === "" ? undefined : v), image().optional()),
			tags: z.array(z.string()).nullish().transform((v) => v ?? []),
			category: z.string().nullish().transform((v) => v ?? ""),
			lang: z.string().nullish().transform((v) => v ?? ""),
		}),
});

const spec = defineCollection({
	loader: glob({ pattern: "*.md", base: "./src/content/spec" }),
});

export const collections = { posts, spec };
