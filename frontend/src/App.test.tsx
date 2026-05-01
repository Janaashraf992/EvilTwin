import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

import App from "./App";

describe("App shell routing", () => {
  it("does not render the authenticated shell on the login route", () => {
    render(
      <MemoryRouter initialEntries={["/login"]}>
        <App />
      </MemoryRouter>
    );

    expect(screen.getByText("EvilTwin SOC")).toBeInTheDocument();
    expect(screen.queryByText("LIVE THREAT OPERATIONS")).not.toBeInTheDocument();
  });
});