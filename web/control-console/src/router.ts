import { createRouter, createWebHashHistory } from "vue-router";

const modules = new Set([
  "overview", "tasks", "agents", "approvals", "policies", "tools", "credentials", "packs",
  "trace", "evidence", "incidents", "compliance", "audit", "models", "data", "context",
  "anomalies", "security_evaluations", "supply_chain", "domain_packs", "sre", "deployments",
  "admin",
]);

export const router = createRouter({
  history: createWebHashHistory(),
  routes: [
    { path: "/", redirect: "/modules/overview" },
    { path: "/modules/:module", name: "module", component: { template: "<span hidden></span>" } },
    { path: "/:pathMatch(.*)*", redirect: "/modules/overview" },
  ],
});

router.beforeEach((to) => {
  const moduleName = String(to.params.module ?? "overview");
  if (to.name === "module" && !modules.has(moduleName)) return "/modules/overview";
  return true;
});
