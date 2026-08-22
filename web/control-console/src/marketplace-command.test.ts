import { describe, expect, it } from "vitest";
import { MARKETPLACE_KINDS, marketplaceResource, marketplaceTemplate,
  validateMarketplaceTypedCommand } from "./marketplace-command";

describe("Marketplace typed command closure", () => {
  it("validates and resource-binds all sixteen lifecycle kinds", () => {
    expect(MARKETPLACE_KINDS).toHaveLength(16);
    for (const kind of MARKETPLACE_KINDS) {
      const command = validateMarketplaceTypedCommand(marketplaceTemplate(kind));
      expect(command.kind).toBe(kind);
      expect(marketplaceResource(command)).not.toBe("");
    }
  });

  it("rejects extensions and keeps install separate from activation", () => {
    const install = marketplaceTemplate("INSTALL");
    expect(validateMarketplaceTypedCommand(install).kind).toBe("INSTALL");
    expect(install).not.toHaveProperty("production_certificate_digest");
    expect(() => validateMarketplaceTypedCommand({ ...install, activated: true }))
      .toThrow("CONTROL_PACK_COMMAND_INVALID");
  });
});
