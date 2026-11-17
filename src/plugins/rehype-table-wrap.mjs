import { visit } from "unist-util-visit";

/** Wraps tables in a horizontally scrollable container (small screens). */
export function rehypeTableWrap() {
	return (tree) => {
		visit(tree, "element", (node, index, parent) => {
			if (node.tagName !== "table" || !parent || index === undefined) return;
			if (parent.properties?.className?.includes?.("table-wrap")) return;
			parent.children[index] = {
				type: "element",
				tagName: "div",
				properties: { className: ["table-wrap"], tabIndex: 0 },
				children: [node],
			};
		});
	};
}
