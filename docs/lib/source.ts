import { loader } from 'fumadocs-core/source';
import { lucideIconsPlugin } from 'fumadocs-core/source/lucide-icons';
import {
  docsContentRoute,
  docsImageRoute,
  docsRoute,
  withSiteBasePath,
  withSiteBasePathInMarkdown,
} from './shared';
import { defineDocs } from 'fumadocs-mdx/macro';
import { metaSchema, pageSchema } from 'fumadocs-core/source/schema';

const markdownFileName = 'content.md';
const imageFileName = 'image.png';

const docs = defineDocs({
  dir: 'content/docs',
  docs: {
    schema: pageSchema,
    postprocess: {
      includeProcessedMarkdown: true,
    },
  },
  meta: {
    schema: metaSchema,
  },
});

// See https://fumadocs.dev/docs/headless/source-api for more info
export const source = loader({
  baseUrl: docsRoute,
  source: docs.toFumadocsSource(),
  plugins: [lucideIconsPlugin()],
});

export function getPageImageUrl(page: (typeof source)['$inferPage']) {
  const segments = [...page.slugs, imageFileName];

  return {
    segments,
    url: withSiteBasePath(
      '/' + [page.locale, ...docsImageRoute.split('/'), ...segments].filter(Boolean).join('/'),
    ),
  };
}

export function getPageMarkdownUrl(page: (typeof source)['$inferPage']) {
  const segments = [...page.slugs, markdownFileName];

  return {
    segments,
    url: '/' + [page.locale, ...docsContentRoute.split('/'), ...segments].filter(Boolean).join('/'),
  };
}

function getPageFromGeneratedRoute(segments: string[] | undefined, fileName: string) {
  if (!segments || segments.at(-1) !== fileName) return;
  return source.getPage(segments.slice(0, -1));
}

export function getPageFromMarkdownRoute(segments: string[] | undefined) {
  return getPageFromGeneratedRoute(segments, markdownFileName);
}

export function getPageFromImageRoute(segments: string[] | undefined) {
  return getPageFromGeneratedRoute(segments, imageFileName);
}

function rewriteRelativeMarkdownLinks(
  page: (typeof source)['$inferPage'],
  markdown: string,
) {
  return markdown.replace(
    /(\]\()((?:\.\.?\/)[^)\s]+?\.mdx?(?:[?#][^)\s]*)?)(\))/g,
    (match, opening: string, target: string, closing: string) => {
      const resolved = new URL(target, `https://single-auth.invalid/${page.path}`);
      const slugs = resolved.pathname
        .replace(/^\//, '')
        .replace(/\.mdx?$/, '')
        .split('/')
        .filter(Boolean);

      if (slugs.at(-1) === 'index') slugs.pop();

      const linkedPage = source.getPage(slugs);
      if (!linkedPage) return match;

      return `${opening}${withSiteBasePath(getPageMarkdownUrl(linkedPage).url)}${resolved.search}${resolved.hash}${closing}`;
    },
  );
}

export async function getLLMText(page: (typeof source)['$inferPage']) {
  const processed = rewriteRelativeMarkdownLinks(
    page,
    withSiteBasePathInMarkdown(await page.data.getText('processed')),
  );

  return `# ${page.data.title}

Source: ${withSiteBasePath(page.url)}

${processed}`;
}
