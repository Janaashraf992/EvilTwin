import Link from "@docusaurus/Link";
import Layout from "@theme/Layout";

const cards = [
  {
    title: "Master Guide",
    desc: "Read the end-to-end narrative with architecture, workflows, and operational context.",
    to: "/docs/",
    icon: "🗺️"
  },
  {
    title: "API Reference",
    desc: "Review backend and SDN endpoints, payloads, and operational usage patterns.",
    to: "/dev/api-reference",
    icon: "🔌"
  },
  {
    title: "Run and Validate",
    desc: "Use quality gates, runtime validation, and hardening checklists before production rollout.",
    to: "/dev/testing-and-quality",
    icon: "🛡️"
  }
];

export default function Home() {
  return (
    <Layout title="EvilTwin Documentation" description="Premium documentation for the SDN-powered Cyber Deception Platform">
      <header className="hero heroBanner">
        <div className="container" style={{position: 'relative', zIndex: 1}}>
          <h1 className="hero__title">EvilTwin SOC Platform</h1>
          <p className="hero__subtitle">
            Comprehensive engineering, architecture, operations, and security documentation for the next-generation cyber
            deception ecosystem.
          </p>
          <div className="ctaRow">
            <Link className="button button--secondary button--lg" to="/docs/">
              Launch Master Guide
            </Link>
            <Link className="button button--outline button--lg" to="/dev/developer-onboarding">
              Developer Portal
            </Link>
          </div>
        </div>
      </header>
      <main className="container margin-vert--xl">
        <section className="gridCards">
          {cards.map((card) => (
            <Link key={card.title} to={card.to} className="docCard">
              <div className="cardIcon">{card.icon}</div>
              <h2>{card.title}</h2>
              <p>{card.desc}</p>
              <div className="cardAction">
                Explore Module
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M5 12h14M12 5l7 7-7 7"/>
                </svg>
              </div>
            </Link>
          ))}
        </section>
      </main>
    </Layout>
  );
}
