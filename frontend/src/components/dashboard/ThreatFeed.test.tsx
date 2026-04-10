import { render, screen } from "@testing-library/react";

import { ThreatFeed } from "./ThreatFeed";
import { useAlertStore } from "../../store/alertStore";

describe("ThreatFeed", () => {
  it("renders incoming alerts", () => {
    useAlertStore.setState({
      alerts: [
        {
          id: "1",
          session_id: "sess-1",
          attacker_ip: "1.2.3.4",
          threat_level: 4,
          message: "Critical payload detected",
          created_at: new Date().toISOString(),
          acknowledged: false
        }
      ]
    });

    render(<ThreatFeed />);

    expect(screen.getByText("1.2.3.4")).toBeInTheDocument();
    expect(screen.getByText("Critical payload detected")).toBeInTheDocument();
  });
});
