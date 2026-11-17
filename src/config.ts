/** Site-wide settings. Edit this file to change names, links and texts. */
export const site = {
	title: "y0sh1mitsu's blog",
	brand: "y0sh1mitsu",
	description:
		"Notes on incident response, digital forensics and Windows internals by Julien Houry, DFIR consultant.",
	lang: "en",
	author: "Julien Houry",
	role: "DFIR Consultant",
	intro:
		"I respond to intrusions for a living. This is where I write up what I learn along the way: incident response, forensic artifacts and Windows internals.",
};

export const nav = [
	{ name: "Posts", href: "/" },
	{ name: "Archive", href: "/archive/" },
	{ name: "About", href: "/about/" },
];

export const socials = [
	{ name: "GitHub", icon: "github", href: "https://github.com/y0sh1mitsu" },
	{
		name: "LinkedIn",
		icon: "linkedin",
		href: "https://www.linkedin.com/in/julienhoury/",
	},
	{ name: "X", icon: "x", href: "https://x.com/y0sh1mitsu" },
	{ name: "RSS", icon: "rss", href: "/rss.xml" },
] as const;
