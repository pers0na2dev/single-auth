import { source } from '@/lib/source';
import { llms } from 'fumadocs-core/source';
import { withSiteBasePathInMarkdown } from '@/lib/shared';

export const revalidate = false;

export function GET() {
  return new Response(withSiteBasePathInMarkdown(llms(source).index()), {
    headers: {
      'Content-Type': 'text/plain; charset=utf-8',
    },
  });
}
