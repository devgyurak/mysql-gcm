# mysql-gcm site

The landing page and documentation, built with [Astro Starlight](https://starlight.astro.build).
Only the two landing pages (`src/content/docs/index.mdx`, `ko/index.mdx`) are written here. Every
other page is generated at build time from the repository's own Markdown by
`scripts/sync-docs.mjs` — edit `README.md`, `docs/`, `spec/` or `CHANGELOG.md`, never the copies.

## Preview locally

Node 22 or later (`.nvmrc`).

```sh
cd site
npm ci
npm run dev        # http://localhost:4321/mysql-gcm/  (Korean: /mysql-gcm/ko/)
```

The landing pages reload as you edit. After editing a repository document, run `npm run sync` to
copy it in again. To preview the production build: `npm run build && npm run preview`.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `SITE_URL` | `https://devgyurak.github.io` | the origin the site is served from (canonical URLs, sitemap) |
| `SITE_BASE` | `/mysql-gcm` | the path under that origin; `/` when the site has its own domain |

`npm run build` syncs the documents, builds, and fails if any internal link does not resolve.

## Deploy on Cloudflare Pages at mysql-gcm.devgyurak.com

Cloudflare builds from this repository itself, so no Cloudflare credential is stored on GitHub,
and every pull request gets a preview URL.

1. Cloudflare dashboard → **Workers & Pages → Create → Pages → Connect to Git** → choose
   `devgyurak/mysql-gcm`.
2. Build settings:

   | Setting | Value |
   |---|---|
   | Production branch | `main` (the site exists there only once `develop` is merged into it) |
   | Framework preset | Astro |
   | Root directory | `site` |
   | Build command | `npm run build` |
   | Build output directory | `dist` |

3. Environment variables (production and preview):

   | Name | Value |
   |---|---|
   | `NODE_VERSION` | `22` |
   | `SITE_BASE` | `/` |
   | `SITE_URL` | `https://mysql-gcm.devgyurak.com` |

4. After the first deploy: the project → **Custom domains → Set up a custom domain** →
   `mysql-gcm.devgyurak.com`. The `devgyurak.com` zone is on Cloudflare, so the CNAME to
   `<project>.pages.dev` is created for you and the certificate is issued within minutes. Do not
   add the record by hand first; Pages only activates a domain it was asked to set up.

`public/_headers` sets the response headers Cloudflare Pages serves (no framing, no MIME sniffing,
HSTS, immutable caching for hashed assets).
