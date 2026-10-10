// @ts-check
import starlight from "@astrojs/starlight";
import { defineConfig } from "astro/config";

// Where the site is served. On its own domain (Cloudflare Workers) set SITE_URL to that origin and
// SITE_BASE to "/"; the defaults describe a project page at devgyurak.github.io/mysql-gcm.
// scripts/sync-docs.mjs and scripts/check-links.mjs read the same SITE_BASE, so rewritten and
// checked links always agree with what Astro serves.
const site = process.env.SITE_URL ?? "https://devgyurak.github.io";
const base = process.env.SITE_BASE ?? "/mysql-gcm";

export default defineConfig({
  site,
  base,
  integrations: [
    starlight({
      title: "mysql-gcm",
      // The wordmark outlined from the banner's IBM Plex Sans Bold (scripts/make-logo.mjs).
      logo: {
        dark: "./src/assets/logo-dark.svg",
        light: "./src/assets/logo-light.svg",
        replacesTitle: true,
      },
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
      customCss: [
        "@fontsource/ibm-plex-sans/400.css",
        "@fontsource/ibm-plex-sans/500.css",
        "@fontsource/ibm-plex-sans/600.css",
        "@fontsource/ibm-plex-sans/700.css",
        "@fontsource/ibm-plex-sans-kr/400.css",
        "@fontsource/ibm-plex-sans-kr/600.css",
        "@fontsource/ibm-plex-sans-kr/700.css",
        "@fontsource/ibm-plex-mono/400.css",
        "@fontsource/ibm-plex-mono/500.css",
        "@fontsource/ibm-plex-mono/600.css",
        "./src/styles/custom.css",
      ],
      components: { Hero: "./src/components/Hero.astro" },
    }),
  ],
});
