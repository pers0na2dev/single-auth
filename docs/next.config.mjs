import { createMDX } from 'fumadocs-mdx/next';

const withMDX = createMDX();
const configuredBasePath = process.env.NEXT_PUBLIC_BASE_PATH?.trim() ?? '';

if (configuredBasePath && !/^\/[A-Za-z0-9._~!$&'()*+,;=:@%/-]+$/.test(configuredBasePath)) {
  throw new Error('NEXT_PUBLIC_BASE_PATH must be empty or start with a slash');
}

const basePath = configuredBasePath === '/' ? '' : configuredBasePath.replace(/\/$/, '');

/** @type {import('next').NextConfig} */
const config = {
  output: 'export',
  basePath,
  trailingSlash: true,
  reactStrictMode: true,
  images: {
    unoptimized: true,
  },
};

export default withMDX(config);
