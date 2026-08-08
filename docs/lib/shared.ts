export const appName = 'single-auth';
export const siteDescription =
  'Complete server-side documentation for single-auth across net/http, fasthttp, Fiber, native storage adapters, OAuth, OIDC, SAML, and plugins.';
export const docsRoute = '/docs';
export const docsImageRoute = '/og/docs';
export const docsContentRoute = '/llms.mdx/docs';

const configuredBasePath = process.env.NEXT_PUBLIC_BASE_PATH?.trim() ?? '';
export const siteBasePath =
  configuredBasePath === '/' ? '' : configuredBasePath.replace(/\/$/, '');

export function withSiteBasePath(pathname: string) {
  const normalizedPath = pathname.startsWith('/') ? pathname : `/${pathname}`;

  if (!siteBasePath) return normalizedPath;
  if (normalizedPath === '/') return `${siteBasePath}/`;

  return `${siteBasePath}${normalizedPath}`;
}

export function withSiteBasePathInMarkdown(markdown: string) {
  if (!siteBasePath) return markdown;

  return markdown.replaceAll('](/', `](${siteBasePath}/`);
}

export const gitConfig = {
  user: 'pers0na2dev',
  repo: 'single-auth',
  branch: 'main',
  docsPath: 'docs/content/docs',
} as const;

export const repositoryUrl = `https://github.com/${gitConfig.user}/${gitConfig.repo}`;

export function getGitHubSourceUrl(path: string) {
  const encodedPath = path
    .split('/')
    .filter(Boolean)
    .map(encodeURIComponent)
    .join('/');

  return `${repositoryUrl}/blob/${gitConfig.branch}/${gitConfig.docsPath}/${encodedPath}`;
}

export function getSiteUrl() {
  const configuredUrl = process.env.NEXT_PUBLIC_SITE_URL?.trim();
  if (configuredUrl) return new URL(configuredUrl);

  const vercelHost =
    process.env.VERCEL_PROJECT_PRODUCTION_URL?.trim() ?? process.env.VERCEL_URL?.trim();
  if (vercelHost) {
    return new URL(vercelHost.startsWith('http') ? vercelHost : `https://${vercelHost}`);
  }

  return new URL('http://localhost:3000');
}
