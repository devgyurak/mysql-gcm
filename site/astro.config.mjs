// @ts-check
import starlight from "@astrojs/starlight";
import { defineConfig } from "astro/config";

// Served from GitHub Pages under /mysql-gcm. SITE_BASE overrides it (a custom domain would use
// "/"); scripts/sync-docs.mjs reads the same variable so rewritten links agree with the base.
const base = process.env.SITE_BASE ?? "/mysql-gcm";

export default defineConfig({
  site: "https://devgyurak.github.io",
  base,
  integrations: [
    starlight({
      title: "mysql-gcm",
      description:
        "AES-GCM for MySQL as a server component, with server-side LIKE on the decrypted value.",
      defaultLocale: "root",
      locales: {
        root: { label: "English", lang: "en" },
        ko: { label: "한국어", lang: "ko" },
      },
      social: [{ icon: "github", label: "GitHub", href: "https://github.com/devgyurak/mysql-gcm" }],
      sidebar: [
        {
          label: "Start here",
          translations: { ko: "시작하기" },
          items: [
            { slug: "overview", label: "Overview", translations: { ko: "개요" } },
            { slug: "ops-constraints", label: "Operational constraints", translations: { ko: "운영 제약" } },
          ],
        },
        {
          label: "Reference",
          translations: { ko: "참조" },
          items: [
            { slug: "envelope", label: "Envelope specification", translations: { ko: "봉투 명세" } },
            { slug: "performance", label: "Performance", translations: { ko: "성능" } },
          ],
        },
        {
          label: "Background",
          translations: { ko: "배경" },
          items: [
            { slug: "design", label: "Design and amendments", translations: { ko: "설계와 개정" } },
            { slug: "changelog", label: "Changelog", translations: { ko: "변경 이력" } },
          ],
        },
      ],
      // The landing pages live in site/; synced pages set their own editUrl to the source file.
      editLink: { baseUrl: "https://github.com/devgyurak/mysql-gcm/edit/develop/site/" },
      lastUpdated: false,
      customCss: ["./src/styles/custom.css"],
    }),
  ],
});
