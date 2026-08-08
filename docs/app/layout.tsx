import { RootProvider } from 'fumadocs-ui/provider/next';
import './global.css';
import { Inter } from 'next/font/google';
import type { Metadata } from 'next';
import {
  appName,
  getSiteUrl,
  repositoryUrl,
  siteDescription,
  withSiteBasePath,
} from '@/lib/shared';

const inter = Inter({
  subsets: ['latin'],
});

export const metadata: Metadata = {
  metadataBase: getSiteUrl(),
  applicationName: appName,
  title: {
    default: `${appName} — authentication for Go`,
    template: `%s — ${appName}`,
  },
  description: siteDescription,
  authors: [{ name: `${appName} contributors`, url: repositoryUrl }],
  creator: `${appName} contributors`,
  keywords: [
    'Go authentication',
    'net/http',
    'fasthttp',
    'Fiber',
    'OAuth 2.0',
    'OpenID Connect',
    'SAML',
    'passkeys',
  ],
  alternates: {
    canonical: withSiteBasePath('/'),
  },
  openGraph: {
    type: 'website',
    url: withSiteBasePath('/'),
    siteName: appName,
    title: `${appName} — authentication for Go`,
    description: siteDescription,
  },
  twitter: {
    card: 'summary_large_image',
    title: `${appName} — authentication for Go`,
    description: siteDescription,
  },
  robots: {
    index: true,
    follow: true,
  },
};

export default function Layout({ children }: LayoutProps<'/'>) {
  return (
    <html lang="en" className={inter.className} suppressHydrationWarning>
      <body className="flex flex-col min-h-screen">
        <RootProvider
          search={{
            options: {
              type: 'static',
              api: withSiteBasePath('/api/search'),
            },
          }}
        >
          {children}
        </RootProvider>
      </body>
    </html>
  );
}
