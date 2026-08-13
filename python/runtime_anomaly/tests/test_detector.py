import unittest

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

    def test_replay_and_invalid_configuration_fail_closed(self) -> None:
        detector = SemanticRiskDetector(window_size=2)
        item = Observation("t1", "task1", 1, "safe", 0, 0, 0)
        detector.observe(item)
        with self.assertRaisesRegex(ValueError, "ANOMALY_SEQUENCE_REPLAY"):
            detector.observe(item)
        with self.assertRaisesRegex(ValueError, "ANOMALY_DETECTOR_CONFIG_INVALID"):
            SemanticRiskDetector(window_size=1)


if __name__ == "__main__":
    unittest.main()
