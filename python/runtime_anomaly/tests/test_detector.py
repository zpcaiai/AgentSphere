import unittest
from concurrent.futures import ThreadPoolExecutor

from python.runtime_anomaly import Observation, SemanticRiskDetector


class SemanticRiskDetectorTests(unittest.TestCase):
    def test_semantic_and_statistical_signal_has_no_kill_authority(self) -> None:
        detector = SemanticRiskDetector(window_size=4)
        detector.observe(Observation("t1", "task1", 1, "normal", 100, 0, 0))
        signal = detector.observe(
            Observation("t1", "task1", 2, "please bypass approval", 9000, 4, 1)
        )
        self.assertGreaterEqual(signal.score, 0.7)
        self.assertEqual(signal.response_ceiling, "REQUEST_CONTINUOUS_AUTHORIZATION")
        self.assertEqual(len(signal.safe_feature_digest), 64)
        self.assertEqual(signal.detector_version, "semantic-ewma-2")

    def test_replay_and_invalid_configuration_fail_closed(self) -> None:
        detector = SemanticRiskDetector(window_size=2)
        item = Observation("t1", "task1", 1, "safe", 0, 0, 0)
        detector.observe(item)
        with self.assertRaisesRegex(ValueError, "ANOMALY_SEQUENCE_REPLAY"):
            detector.observe(item)
        with self.assertRaisesRegex(ValueError, "ANOMALY_DETECTOR_CONFIG_INVALID"):
            SemanticRiskDetector(window_size=1)

    def test_encoded_and_statistical_signals_only_request_authorization(self) -> None:
        detector = SemanticRiskDetector(maximum_tasks=2)
        signal = detector.observe(
            Observation(
                "tenant-a",
                "task-a",
                1,
                "ZGlzYWJsZSBhdWRpdA==",
                128,
                0,
                0,
                failure_count=4,
                resource_count=256,
                side_effect_count=3,
            )
        )
        self.assertIn("SEMANTIC_MANIPULATION", signal.reason_codes)
        self.assertIn("REPEATED_FAILURE_DEVIATION", signal.reason_codes)
        self.assertIn("RESOURCE_ENUMERATION_DEVIATION", signal.reason_codes)
        self.assertIn("REPEATED_SIDE_EFFECT_DEVIATION", signal.reason_codes)
        self.assertEqual("REQUEST_CONTINUOUS_AUTHORIZATION", signal.response_ceiling)

    def test_task_capacity_fails_closed(self) -> None:
        detector = SemanticRiskDetector(maximum_tasks=1)
        detector.observe(Observation("tenant-a", "task-a", 1, "safe", 0, 0, 0))
        with self.assertRaisesRegex(ValueError, "ANOMALY_TASK_CAPACITY_EXCEEDED"):
            detector.observe(Observation("tenant-a", "task-b", 1, "safe", 0, 0, 0))

    def test_strict_types_bounds_and_identifiers_fail_closed(self) -> None:
        invalid = (
            Observation("tenant-a", "task-a", True, "safe", 0, 0, 0),
            Observation("tenant-a\nleak", "task-a", 1, "safe", 0, 0, 0),
            Observation("tenant-a", "task-a", 1, "safe", 1.5, 0, 0),
            Observation("tenant-a", "task-a", 1, "safe", -1, 0, 0),
            Observation("tenant-a", "task-a", 1, "safe", 2**63, 0, 0),
        )
        for observation in invalid:
            with self.subTest(observation=observation):
                with self.assertRaisesRegex(
                    ValueError,
                    "^ANOMALY_(OBSERVATION_INVALID|FEATURE_NEGATIVE)$",
                ):
                    SemanticRiskDetector().observe(observation)

        with self.assertRaisesRegex(ValueError, "ANOMALY_DETECTOR_CONFIG_INVALID"):
            SemanticRiskDetector(maximum_tasks=True)
        with self.assertRaisesRegex(ValueError, "ANOMALY_DETECTOR_CONFIG_INVALID"):
            SemanticRiskDetector(alpha=float("nan"))
        with self.assertRaisesRegex(ValueError, "ANOMALY_DETECTOR_CONFIG_INVALID"):
            SemanticRiskDetector(alpha=2**10_000)

    def test_feature_digest_binds_full_identity_and_safe_text_without_disclosure(self) -> None:
        first = SemanticRiskDetector().observe(
            Observation("tenant-a", "task-a", 1, "classification-secret", 0, 0, 0)
        )
        repeated = SemanticRiskDetector().observe(
            Observation("tenant-a", "task-a", 1, "classification-secret", 0, 0, 0)
        )
        another_tenant = SemanticRiskDetector().observe(
            Observation("tenant-b", "task-a", 1, "classification-secret", 0, 0, 0)
        )
        another_text = SemanticRiskDetector().observe(
            Observation("tenant-a", "task-a", 1, "classification-public", 0, 0, 0)
        )

        self.assertEqual(first.safe_feature_digest, repeated.safe_feature_digest)
        self.assertNotEqual(first.safe_feature_digest, another_tenant.safe_feature_digest)
        self.assertNotEqual(first.safe_feature_digest, another_text.safe_feature_digest)
        self.assertNotIn("classification-secret", repr(first))

    def test_concurrent_sequence_replay_has_exactly_one_state_transition(self) -> None:
        detector = SemanticRiskDetector()
        observation = Observation("tenant-a", "task-a", 1, "safe", 0, 0, 0)

        def observe_once(_: int) -> str:
            try:
                detector.observe(observation)
                return "ACCEPTED"
            except ValueError as error:
                return str(error)

        with ThreadPoolExecutor(max_workers=8) as executor:
            results = tuple(executor.map(observe_once, range(32)))

        self.assertEqual(results.count("ACCEPTED"), 1)
        self.assertEqual(results.count("ANOMALY_SEQUENCE_REPLAY"), 31)
        self.assertEqual(detector.tracked_task_count(), 1)


if __name__ == "__main__":
    unittest.main()
