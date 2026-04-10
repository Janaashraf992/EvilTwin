import { render, screen } from "@testing-library/react";
import { vi } from "vitest";

import { TopBar } from "./TopBar";

const useWebSocketMock = vi.fn();

vi.mock("../../hooks/useWebSocket", () => ({
  useWebSocket: () => useWebSocketMock()
}));

describe("TopBar connection status", () => {
  it("renders reconnect backoff details when disconnected", () => {
    useWebSocketMock.mockReturnValue({
      connected: false,
      lastPing: null,
      retryCount: 4,
      nextRetryInMs: 8000,
      lastError: "Connection error"
    });

    render(<TopBar />);

    expect(screen.getByText("Disconnected")).toBeInTheDocument();
    expect(screen.getByText(/Connection error/)).toBeInTheDocument();
    expect(screen.getByText(/Retries: 4/)).toBeInTheDocument();
    expect(screen.getByText(/Next: 8s/)).toBeInTheDocument();
  });

  it("hides retry details when connected", () => {
    useWebSocketMock.mockReturnValue({
      connected: true,
      lastPing: new Date("2026-03-18T12:00:00Z"),
      retryCount: 0,
      nextRetryInMs: null,
      lastError: null
    });

    render(<TopBar />);

    expect(screen.getByText("Stream Active")).toBeInTheDocument();
    expect(screen.queryByText(/Retries:/)).not.toBeInTheDocument();
    expect(screen.getByText(/Last Event:/)).toBeInTheDocument();
  });
});
