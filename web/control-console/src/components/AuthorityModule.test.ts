import { mount } from "@vue/test-utils";
import { describe, expect, it } from "vitest";
import AuthorityModule from "./AuthorityModule.vue";

describe("AuthorityModule", () => {
  it("shows partial failure without cached success", () => {
    const wrapper = mount(AuthorityModule, { props: { sectionName: "INCIDENTS", section: {
      schema_version: "agenttrust.authority-view.v1", section: "INCIDENTS", authoritative: true,
      available: false, data: null, data_digest: "0".repeat(64), safe_error_code: "AUTHORITATIVE_SOURCE_UNAVAILABLE",
      fetched_at: "2026-08-13T00:00:00Z",
    } } });
    expect(wrapper.get("[role=alert]").text()).toContain("AUTHORITATIVE_SOURCE_UNAVAILABLE");
    expect(wrapper.find("table").exists()).toBe(false);
  });

  it("redacts a secret field before rendering", () => {
    const wrapper = mount(AuthorityModule, { props: { sectionName: "EVIDENCE", section: {
      schema_version: "agenttrust.authority-view.v1", section: "EVIDENCE", authoritative: true,
      available: true, data: [{ id: "e1", one_time_secret: "do-not-render", safe_summary: "verified" }],
      data_digest: "a".repeat(64), fetched_at: "2026-08-13T00:00:00Z",
    } } });
    expect(wrapper.text()).not.toContain("do-not-render");
    expect(wrapper.text()).toContain("[REDACTED]");
  });
});
