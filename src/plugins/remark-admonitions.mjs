import { visit } from "unist-util-visit";

const KINDS = ["note", "tip", "important", "caution", "warning"];

/**
 * Turns `:::note` … `:::` blocks (remark-directive) into styled callouts.
 * Any other directive syntax is restored to plain text, so that a stray
 * ":word" in a sentence is never swallowed.
 */
export function remarkAdmonitions() {
	return (tree) => {
		visit(tree, (node, index, parent) => {
			if (node.type === "containerDirective" && KINDS.includes(node.name)) {
				const label = node.name[0].toUpperCase() + node.name.slice(1);
				node.data = {
					hName: "aside",
					hProperties: { className: ["admonition", `admonition-${node.name}`] },
				};
				node.children.unshift({
					type: "paragraph",
					data: { hProperties: { className: ["admonition-title"] } },
					children: [{ type: "text", value: label }],
				});
				return;
			}
			if (node.type === "textDirective" && parent && index !== undefined) {
				parent.children.splice(
					index,
					1,
					{ type: "text", value: `:${node.name}` },
					...node.children,
				);
				return index;
			}
			if (node.type === "leafDirective" || node.type === "containerDirective") {
				node.data = { hName: "div" };
			}
		});
	};
}
