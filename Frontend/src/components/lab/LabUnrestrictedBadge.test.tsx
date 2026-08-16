import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { LabUnrestrictedBadge } from "./LabUnrestrictedBadge";

describe("LabUnrestrictedBadge", () => {
  it("renders the LAB UNRESTRICTED label", () => {
    render(<LabUnrestrictedBadge />);
    expect(screen.getByTestId("lab-unrestricted-badge")).toHaveTextContent(
      "LAB UNRESTRICTED",
    );
  });
});
