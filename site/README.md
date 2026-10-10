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

## Deploy on Cloudflare Workers at mysql-gcm.devgyurak.com

The site is static, so it is served as Workers static assets (`wrangler.jsonc`) with no Worker
script. Cloudflare builds from this repository itself (Workers Builds), so no Cloudflare
credential is stored on GitHub, and every other branch gets a preview URL.

1. Cloudflare dashboard → **Workers & Pages → Create application → Import a repository** → choose
   `devgyurak/mysql-gcm`.
2. Settings:

   | Setting | Value |
   |---|---|
   | Project name | `mysql-gcm` (must match `name` in `wrangler.jsonc`) |
   | Production branch | `main` (the site exists there only once `develop` is merged into it) |
   | Build command | `npm run build` |
   | Deploy command | `npx wrangler deploy` |
   | Non-production branch deploy command | `npx wrangler versions upload` |
   | Root directory (advanced) | `site` |

3. Build variables (advanced):

   | Name | Value |
   |---|---|
   | `NODE_VERSION` | `22` |
   | `SITE_BASE` | `/` |
   | `SITE_URL` | `https://mysql-gcm.devgyurak.com` |

4. After the first deploy: the Worker → **Settings → Domains & Routes → Add → Custom domain** →
   `mysql-gcm.devgyurak.com`. The `devgyurak.com` zone is on Cloudflare, so the DNS record and the
   certificate are created for you. Do not add the record by hand first.

`wrangler` is a pinned dev dependency, so `npx wrangler` uses the locked version. To check the
bundle without deploying: `npm run build && npx wrangler deploy --dry-run`.

`public/_headers` sets the response headers Cloudflare serves (no framing, no MIME sniffing, HSTS,
immutable caching for hashed assets).
