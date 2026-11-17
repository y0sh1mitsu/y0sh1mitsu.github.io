import rss from "@astrojs/rss";
import type { APIContext } from "astro";
import { site } from "../config";
import { getPosts, postUrl } from "../lib/posts";

export async function GET(context: APIContext) {
	const posts = await getPosts();
	return rss({
		title: site.title,
		description: site.description,
		site: context.site ?? "https://y0sh1mitsu.github.io/",
		items: posts.map((post) => ({
			title: post.data.title,
			pubDate: post.data.published,
			description: post.data.description,
			link: postUrl(post),
			categories: [post.data.category, ...post.data.tags].filter(Boolean),
		})),
		customData: `<language>${site.lang}</language>`,
	});
}
