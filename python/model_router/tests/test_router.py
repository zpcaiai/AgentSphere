import unittest
from itertools import repeat

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

    def test_no_allowed_candidate_fails_explicitly_without_relaxing_policy(self) -> None:
        with self.assertRaisesRegex(ValueError, "^MODEL_ROUTE_NO_ALLOWED_CANDIDATE$"):
            ModelRouter().rank([Candidate("denied", False, 1_000_000, 1, 1, 0)])

    def test_ranking_is_deterministic(self) -> None:
        candidates = [
            Candidate("b", True, 500_000, 10, 20, 30),
            Candidate("a", True, 500_000, 10, 20, 30),
        ]
        self.assertEqual(
            [item.provider_key for item in ModelRouter().rank(candidates)], ["a", "b"]
        )

    def test_duplicate_empty_and_unbounded_candidate_sets_fail_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "MODEL_ROUTE_CANDIDATE_SET_INVALID"):
            ModelRouter().rank([])
        duplicated = Candidate("same", True, 500_000, 10, 20, 30)
        with self.assertRaisesRegex(ValueError, "MODEL_ROUTE_CANDIDATE_DUPLICATE"):
            ModelRouter().rank([duplicated, duplicated])
        with self.assertRaisesRegex(ValueError, "MODEL_ROUTE_CANDIDATE_SET_INVALID"):
            ModelRouter().rank(
                Candidate(str(index), True, 500_000, 10, 20, 30)
                for index in range(1_001)
            )

        with self.assertRaisesRegex(ValueError, "MODEL_ROUTE_CANDIDATE_SET_INVALID"):
            ModelRouter().rank(repeat(Candidate("infinite", True, 1, 1, 1, 1)))

    def test_every_candidate_is_strictly_validated_before_policy_filtering(self) -> None:
        invalid = (
            Candidate("denied", "false", 1, 1, 1, 1),
            Candidate("denied\nheader", False, 1, 1, 1, 1),
            Candidate("denied", False, 1.5, 1, 1, 1),
            Candidate("denied", False, True, 1, 1, 1),
        )
        for candidate in invalid:
            with self.subTest(candidate=candidate):
                with self.assertRaisesRegex(ValueError, "MODEL_ROUTE_CANDIDATE_INVALID"):
                    ModelRouter().rank([candidate])

    def test_iterator_failures_are_sanitized(self) -> None:
        def failing_candidates():
            yield Candidate("provider", True, 1, 1, 1, 1)
            raise RuntimeError("provider-secret")

        with self.assertRaisesRegex(ValueError, "^MODEL_ROUTE_CANDIDATE_SET_INVALID$") as raised:
            ModelRouter().rank(failing_candidates())
        self.assertNotIn("provider-secret", str(raised.exception))

    def test_scores_remain_integral(self) -> None:
        ranked = ModelRouter().rank([Candidate("provider", True, 900_000, 10, 20, 30)])
        self.assertIs(type(ranked[0].score_millionths), int)


if __name__ == "__main__":
    unittest.main()
