import { mkdir, rm, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';

const outputDirectory = resolve('dist');
const siteUrl = process.env.VITE_SITE_URL?.trim();
const robotsRules = ['User-agent: *', 'Allow: /', 'Disallow: /api/', ''];

await mkdir(outputDirectory, { recursive: true });

if (!siteUrl) {
  await writeFile(resolve(outputDirectory, 'robots.txt'), robotsRules.join('\n'));
  await rm(resolve(outputDirectory, 'sitemap.xml'), { force: true });
  console.info('SEO files: left sitemap.xml out because VITE_SITE_URL is not configured.');
  process.exit(0);
}

let siteOrigin;
try {
  const url = new URL(siteUrl);
  if (
    url.protocol !== 'https:' ||
    !url.hostname.includes('.') ||
    url.username ||
    url.password ||
    (url.pathname !== '/' && url.pathname !== '') ||
    url.search ||
    url.hash
  ) {
    throw new Error('VITE_SITE_URL must be an HTTPS site origin without a path, query, or fragment.');
  }
  siteOrigin = url.origin;
} catch (error) {
  console.error(error instanceof Error ? error.message : 'VITE_SITE_URL is invalid.');
  process.exitCode = 1;
  process.exit();
}

const publicRoutes = ['/', '/new-scan', '/cookies', '/support'];
const sitemapEntries = publicRoutes
  .map((route) => `  <url><loc>${siteOrigin}${route}</loc></url>`)
  .join('\n');
const sitemap = [
  '<?xml version="1.0" encoding="UTF-8"?>',
  '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">',
  sitemapEntries,
  '</urlset>',
  ''
].join('\n');

robotsRules.push(`Sitemap: ${siteOrigin}/sitemap.xml`, '');
await writeFile(resolve(outputDirectory, 'robots.txt'), robotsRules.join('\n'));
await writeFile(resolve(outputDirectory, 'sitemap.xml'), sitemap);
console.info(`SEO files: generated sitemap for ${siteOrigin}.`);
