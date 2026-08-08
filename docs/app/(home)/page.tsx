import Link from 'next/link';
import { ArrowRight, Database, Network, ShieldCheck } from 'lucide-react';

export default function HomePage() {
  return (
    <main className="mx-auto flex w-full max-w-6xl flex-1 flex-col px-6 py-20 md:py-28">
      <div className="max-w-3xl">
        <div className="mb-6 inline-flex items-center rounded-full border bg-fd-card px-3 py-1 text-sm text-fd-muted-foreground">
          Native Go server library
        </div>
        <h1 className="text-balance text-5xl font-semibold tracking-tight md:text-7xl">
          Authentication infrastructure that speaks Go.
        </h1>
        <p className="mt-6 max-w-2xl text-pretty text-lg leading-8 text-fd-muted-foreground md:text-xl">
          Run one authentication core through net/http, fasthttp, or Fiber. Use native Go storage,
          OAuth, OIDC, SAML, passkeys, organizations, and server-side plugins without a JavaScript
          runtime.
        </p>
        <div className="mt-9 flex flex-wrap gap-3">
          <Link
            href="/docs/getting-started/quickstart"
            className="inline-flex items-center gap-2 rounded-lg bg-fd-primary px-4 py-2.5 font-medium text-fd-primary-foreground"
          >
            Build your first server <ArrowRight className="size-4" />
          </Link>
          <Link
            href="/docs"
            className="inline-flex items-center rounded-lg border bg-fd-card px-4 py-2.5 font-medium"
          >
            Read the handbook
          </Link>
        </div>
      </div>

      <section className="mt-20 grid gap-px overflow-hidden rounded-2xl border bg-fd-border md:grid-cols-3">
        {[
          {
            icon: Network,
            title: 'Three transports',
            text: 'The same dispatcher and behavior across net/http, direct fasthttp, and Fiber v3.',
          },
          {
            icon: Database,
            title: 'Native persistence',
            text: 'Memory, SQLite, PostgreSQL, MySQL, SQL Server, and MongoDB primary adapters, plus Redis-backed secondary storage.',
          },
          {
            icon: ShieldCheck,
            title: 'Server protocols',
            text: 'Sessions, social sign-in, OAuth 2.0, OIDC, SAML SSO, SCIM, passkeys, and 2FA.',
          },
        ].map(({ icon: Icon, title, text }) => (
          <article key={title} className="bg-fd-background p-7">
            <Icon className="mb-5 size-6 text-fd-primary" />
            <h2 className="font-semibold">{title}</h2>
            <p className="mt-2 text-sm leading-6 text-fd-muted-foreground">{text}</p>
          </article>
        ))}
      </section>
    </main>
  );
}
