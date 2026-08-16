import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { describe, expect, it } from "vitest";

import { emptyLabPlan } from "@/lib/lab/labApproval";
import type { LabScanPlan } from "@/lib/lab/types";

import { PlanEditor } from "./PlanEditor";

function Harness({ initial }: { initial: LabScanPlan }) {
  const [plan, setPlan] = useState(initial);
  return <PlanEditor plan={plan} onChange={setPlan} />;
}

describe("PlanEditor", () => {
  it("locks requires_approval false in LAB and can add unsigned/code/headless templates", async () => {
    const user = userEvent.setup();
    render(<Harness initial={emptyLabPlan("lab_unrestricted")} />);

    expect(screen.getByTestId("lab-plan-approval")).toHaveTextContent(
      "requires_approval=false",
    );

    await user.selectOptions(screen.getByTestId("lab-plan-kind"), "template");
    await user.click(screen.getByRole("button", { name: "unsigned" }));
    await user.click(screen.getByRole("button", { name: "code" }));
    await user.click(screen.getByRole("button", { name: "headless" }));

    const steps = screen.getByTestId("lab-plan-steps");
    expect(steps).toHaveTextContent("unsigned");
    expect(steps).toHaveTextContent("code");
    expect(steps).toHaveTextContent("headless");
    expect(screen.getByTestId("lab-plan-approval")).toHaveTextContent(
      "requires_approval=false",
    );
  });
});
