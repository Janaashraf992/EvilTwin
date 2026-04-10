import React from "react";
import BrowserOnly from "@docusaurus/BrowserOnly";

// Swizzle wrapper: renders Mermaid only on the client to avoid the
// "useColorMode called outside <ColorModeProvider>" SSG crash.
export default function Mermaid(props) {
  return (
    <BrowserOnly fallback={<div className="docusaurus-mermaid-container">Loading diagram…</div>}>
      {() => {
        // Lazy-require so hooks run only inside the browser context
        const MermaidOriginal =
          require("@docusaurus/theme-mermaid/lib/theme/Mermaid").default;
        return <MermaidOriginal {...props} />;
      }}
    </BrowserOnly>
  );
}
