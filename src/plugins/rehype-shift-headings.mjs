import { visit } from "unist-util-visit";

/**
 * Posts are written with `#` as their top-level section heading, but the page
 * already has an <h1> (the post title). Shift every heading down one level so
 * the document outline stays valid. Heading ids are untouched.
 */
export function rehypeShiftHeadings() {
	return (tree, file) => {
		if (!file.path || !file.path.includes("/content/posts/")) return;
		let hasH1 = false;
		visit(tree, "element", (node) => {
			if (node.tagName === "h1") hasH1 = true;
		});
		if (!hasH1) return;
		visit(tree, "element", (node) => {
			const match = /^h([1-5])$/.exec(node.tagName);
			if (match) node.tagName = `h${Number(match[1]) + 1}`;
		});
	};
}
