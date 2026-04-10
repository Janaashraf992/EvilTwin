// @ts-check

const config = {
  title: "EvilTwin Documentation",
  tagline: "SDN-Powered Cyber Deception Platform",
  url: "https://Janaashraf992.github.io",
  baseUrl: "/EvilTwin/",
  organizationName: "Janaashraf992",
  projectName: "EvilTwin",
  deploymentBranch: "gh-pages",
  trailingSlash: false,
  onBrokenLinks: "warn",
  markdown: {
    mermaid: true,
  },
  i18n: {
    defaultLocale: "en",
    locales: ["en"]
  },
  themes: ["@docusaurus/theme-mermaid"],
  presets: [
    [
      "classic",
      {
        docs: {
          path: "docs",
          routeBasePath: "docs",
          sidebarPath: require.resolve("./sidebars.js"),
          editUrl: "https://github.com/Janaashraf992/EvilTwin/edit/main/docs-site/docs/"
        },
        blog: false,
        theme: {
          customCss: require.resolve("./src/css/custom.css")
        }
      }
    ]
  ],
  plugins: [
    [
      "@docusaurus/plugin-content-docs",
      {
        id: "dev",
        path: "dev",
        routeBasePath: "dev",
        sidebarPath: require.resolve("./sidebarsDev.js"),
        editUrl: "https://github.com/Janaashraf992/EvilTwin/edit/main/docs-site/dev/"
      }
    ],
    [
      require.resolve("@easyops-cn/docusaurus-search-local"),
      {
        hashed: true,
        docsRouteBasePath: ["/docs", "/dev"],
        docsPluginIdForPreferredVersion: "default",
        highlightSearchTermsOnTargetPage: true,
        explicitSearchResultPath: true
      }
    ]
  ],
  themeConfig: {
    colorMode: {
      defaultMode: 'dark',
      disableSwitch: false,
      respectPrefersColorScheme: true,
    },
    navbar: {
      title: "EvilTwin Docs",
      items: [
        {
          type: "docSidebar",
          sidebarId: "platformSidebar",
          position: "left",
          label: "User Docs"
        },
        {
          type: "docSidebar",
          sidebarId: "devSidebar",
          docsPluginId: "dev",
          position: "left",
          label: "Developer Docs"
        },
        {
          href: "https://github.com/Janaashraf992/EvilTwin",
          label: "GitHub",
          position: "right"
        }
      ]
    },
    footer: {
      style: "dark",
      links: [
        {
          title: "Docs",
          items: [
            {
              label: "Master Guide",
              to: "/docs/master-guide"
            },
            {
              label: "Incident Runbook",
              to: "/docs/incident-response-runbook"
            }
          ]
        },
        {
          title: "Engineering",
          items: [
            {
              label: "API Reference",
              to: "/dev/api-reference"
            },
            {
              label: "Backend Design",
              to: "/dev/backend-design"
            },
            {
              label: "SDN Controller",
              to: "/dev/sdn-controller"
            }
          ]
        }
      ],
      copyright: `Copyright 2026 The EvilTwin Team`
    },
    prism: {
      additionalLanguages: ["bash", "python", "json", "yaml", "sql"]
    },
    mermaid: {
      theme: { light: 'default', dark: 'dark' }
    }
  }
};

module.exports = config;
