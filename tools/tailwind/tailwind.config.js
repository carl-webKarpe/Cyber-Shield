/**
 * Cyber-Shield Tailwind CSS build config.
 * Rebuild css/tailwind.css after changing Tailwind classes (run from the Cyber-Shield folder):
 *   npx tailwindcss@3.4.16 -c tools/tailwind/tailwind.config.js -i tools/tailwind/input.css -o css/tailwind.css --minify
 * The compiled file is committed so lab browsers never need internet access to load styles.
 */
module.exports = {
  content: ["./superadmin.php", "./js/superadmin.js"],
  theme: {
    extend: {
      fontFamily: {
        display: ['"Space Grotesk"', "Inter", "sans-serif"],
        body: ["Inter", "sans-serif"],
        mono: ['"IBM Plex Mono"', "monospace"],
      },
    },
  },
};
