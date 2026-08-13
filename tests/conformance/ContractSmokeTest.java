import com.agenttrust.v1.Contracts;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public final class ContractSmokeTest {
  private ContractSmokeTest() {}

  public static void main(String[] args) {
    var tool = new Contracts.ToolRef("coding.test", "1.0.0");
    var step = new Contracts.PlanStep(
        "step-1", 1, "run tests", List.of(), Optional.of(tool),
        List.of("repo:example"), Contracts.RiskLevel.LOW);
    var plan = new Contracts.PlanManifest(
        "agenttrust.contracts.v1", "plan-1", "a".repeat(64), "b".repeat(64),
        List.of(step), List.of("repo:example"), Contracts.RiskLevel.LOW, 100L,
        "2026-08-05T11:00:00Z");
    var goal = new Contracts.SignedGoal(
        "agenttrust.contracts.v1", "goal-1", "run tests", "a".repeat(64),
        Map.of("network", "none"), "user:1", "2026-08-05T10:00:00Z",
        "key-1", "signature");
    if (!plan.steps().getFirst().tool().orElseThrow().equals(tool)
        || !goal.constraints().get("network").equals("none")) {
      throw new IllegalStateException("generated Java contracts are inconsistent");
    }
  }
}
