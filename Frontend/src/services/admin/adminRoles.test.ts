import { describe, expect, it } from "vitest";
import {
  canAccessRole,
  parseAdminRole,
  roleRank,
} from "./adminRoles";

describe("adminRoles", () => {
  describe("parseAdminRole", () => {
    it("parses the three canonical roles", () => {
      expect(parseAdminRole("operator")).toBe("operator");
      expect(parseAdminRole("ADMIN")).toBe("admin");
      expect(parseAdminRole(" super-admin ")).toBe("super-admin");
      expect(parseAdminRole("super_admin")).toBe("super-admin");
    });

    it("returns null for empty or unknown", () => {
      expect(parseAdminRole(null)).toBeNull();
      expect(parseAdminRole("")).toBeNull();
      expect(parseAdminRole("guest")).toBeNull();
    });
  });

  describe("roleRank and canAccessRole", () => {
    it("orders operator < admin < super-admin", () => {
      expect(roleRank("operator")).toBeLessThan(roleRank("admin"));
      expect(roleRank("admin")).toBeLessThan(roleRank("super-admin"));
    });

    it("allows same or higher tier", () => {
      expect(canAccessRole("operator", "operator")).toBe(true);
      expect(canAccessRole("admin", "operator")).toBe(true);
      expect(canAccessRole("super-admin", "admin")).toBe(true);
    });

    it("denies lower tier or missing role", () => {
      expect(canAccessRole("operator", "admin")).toBe(false);
      expect(canAccessRole("admin", "super-admin")).toBe(false);
      expect(canAccessRole(null, "operator")).toBe(false);
    });
  });
});
