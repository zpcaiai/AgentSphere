import unittest

from python.model_router import Candidate, ModelRouter


class RouterTests(unittest.TestCase):
    def test_denied_candidate_can_never_be_ranked(self) -> None:
        ranked = ModelRouter().rank(
            [
                Candidate("denied", False, 1_000_000, 1, 1, 0),
                Candidate("allowed", True, 500_000, 10, 20, 30),
            ]
        )
        self.assertEqual([item.provider_key for item in ranked], ["allowed"])

    def test_ranking_is_deterministic(self) -> None:
        candidates = [
            Candidate("b", True, 500_000, 10, 20, 30),
            Candidate("a", True, 500_000, 10, 20, 30),
        ]
        self.assertEqual(
            [item.provider_key for item in ModelRouter().rank(candidates)], ["a", "b"]
        )


if __name__ == "__main__":
    unittest.main()
