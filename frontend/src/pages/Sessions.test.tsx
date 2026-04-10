import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { vi } from "vitest";

import { Sessions } from "./Sessions";

const useSessionsMock = vi.fn((filters: any) => ({
  data: {
    items: [],
    total: 0,
    page: filters.page,
    pages: 3
  }
}));

const useSessionMock = vi.fn(() => ({ data: null }));

vi.mock("../hooks/useSessions", () => ({
  useSessions: (filters: any) => useSessionsMock(filters),
  useSession: (id: string | null) => useSessionMock(id)
}));

describe("Sessions page filters", () => {
  beforeEach(() => {
    useSessionsMock.mockClear();
    useSessionMock.mockClear();
  });

  it("updates hook filters when controls change", async () => {
    const user = userEvent.setup();
    render(<Sessions />);

    const ipInput = screen.getByPlaceholderText("Filter by IP");
    await user.type(ipInput, "203.0.113.9");

    const selects = screen.getAllByRole("combobox");
    await user.selectOptions(selects[0], "3");
    await user.selectOptions(selects[1], "cowrie");
    await user.selectOptions(selects[2], "10");

    const datetimeInputs = Array.from(document.querySelectorAll("input[type='datetime-local']")) as HTMLInputElement[];
    await user.type(datetimeInputs[0], "2026-03-18T10:00");
    await user.type(datetimeInputs[1], "2026-03-18T11:00");

    const lastCallArg = useSessionsMock.mock.calls.at(-1)?.[0];
    expect(lastCallArg).toMatchObject({
      page: 1,
      page_size: 10,
      threat_level: 3,
      honeypot: "cowrie",
      ip: "203.0.113.9",
      date_from: "2026-03-18T10:00",
      date_to: "2026-03-18T11:00"
    });
  });

  it("increments page when next is clicked", async () => {
    const user = userEvent.setup();
    render(<Sessions />);

    await user.click(screen.getByRole("button", { name: "Next" }));

    const lastCallArg = useSessionsMock.mock.calls.at(-1)?.[0];
    expect(lastCallArg.page).toBe(2);
  });
});
