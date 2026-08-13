import com.agenttrust.v1.Contracts;

public final class ContractSmokeTest {
  public static void main(String[] args) {
    if (Contracts.RiskLevel.valueOf("CRITICAL") != Contracts.RiskLevel.CRITICAL) throw new AssertionError();
    try { Contracts.Decision.valueOf("UNKNOWN"); throw new AssertionError("unknown decision accepted"); }
    catch (IllegalArgumentException expected) { }
  }
}

