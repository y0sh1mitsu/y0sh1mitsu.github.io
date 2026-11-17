import { type CollectionEntry, getCollection } from "astro:content";

export type Post = CollectionEntry<"posts">;

/** Published posts, newest first. Drafts only show up in `astro dev`. */
export async function getPosts(): Promise<Post[]> {
	const posts = await getCollection("posts", ({ data }) =>
		import.meta.env.PROD ? !data.draft : true,
	);
	return posts.sort(
		(a, b) => b.data.published.getTime() - a.data.published.getTime(),
	);
}

export const postUrl = (post: Post) => `/posts/${post.id}/`;
export const tagUrl = (tag: string) =>
	`/archive/tag/${encodeURIComponent(tag.trim())}/`;
export const categoryUrl = (category: string) =>
	category.trim()
		? `/archive/category/${encodeURIComponent(category.trim())}/`
		: "/archive/category/uncategorized/";

export function readingTime(post: Post): number {
	const words = (post.body ?? "").split(/\s+/).filter(Boolean).length;
	return Math.max(1, Math.round(words / 200));
}

const longDate = new Intl.DateTimeFormat("en-GB", {
	day: "numeric",
	month: "long",
	year: "numeric",
	timeZone: "UTC",
});
export const formatDate = (date: Date) => longDate.format(date);
export const isoDate = (date: Date) => date.toISOString().slice(0, 10);

export function countBy(values: string[]): { name: string; count: number }[] {
	const counts = new Map<string, number>();
	for (const v of values) counts.set(v, (counts.get(v) ?? 0) + 1);
	return [...counts.entries()]
		.map(([name, count]) => ({ name, count }))
		.sort((a, b) => a.name.localeCompare(b.name));
}

export async function getTaxonomy() {
	const posts = await getPosts();
	return {
		categories: countBy(
			posts.map((p) => p.data.category.trim()).filter(Boolean),
		),
		tags: countBy(posts.flatMap((p) => p.data.tags.map((t) => t.trim()))),
	};
}
