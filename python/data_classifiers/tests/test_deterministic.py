import unittest

from python.data_classifiers import Classification, DeterministicClassifier


class ClassifierTests(unittest.TestCase):
    def test_secret_is_restricted(self) -> None:
        result = DeterministicClassifier().classify(b"api_key=secret", True)
        self.assertEqual(result.classification, Classification.RESTRICTED)

    def test_untrusted_unknown_fails_closed(self) -> None:
        result = DeterministicClassifier().classify(b"ordinary", False)
        self.assertEqual(result.classification, Classification.RESTRICTED)
        self.assertEqual(result.confidence, "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
