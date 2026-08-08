import type { BaseLayoutProps } from 'fumadocs-ui/layouts/shared';
import { appName, docsRoute, repositoryUrl } from './shared';

export function baseOptions(): BaseLayoutProps {
  return {
    nav: {
      title: appName,
      url: '/',
    },
    links: [
      {
        text: 'Documentation',
        url: docsRoute,
        active: 'nested-url',
      },
    ],
    githubUrl: repositoryUrl,
    searchToggle: {
      enabled: true,
    },
  };
}
