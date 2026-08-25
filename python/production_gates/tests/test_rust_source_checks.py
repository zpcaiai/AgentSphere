import unittest

from scripts.rust_source_checks import (
    extract_rust_functions,
    rust_call_contains,
    rust_code_contains,
    rust_function_call_contains,
    rust_function_code_contains,
    rust_json_object_key_sets,
    tokenize_rust,
)


class RustSourceChecksTest(unittest.TestCase):
    def test_compact_and_rustfmt_multiline_calls_match(self) -> None:
        arguments = ("authority.clone()", "tokens", "runtime")
        self.assertTrue(rust_call_contains(
            "let app=router(authority.clone(),tokens,runtime);", "router", arguments,
        ))
        self.assertTrue(rust_call_contains(
            """let app = router(
                authority.clone(),
                tokens,
                runtime,
            );""",
            "router",
            arguments,
        ))
        self.assertTrue(rust_code_contains("value . chars ( ) . count ( ) <= 2_000", "value.chars().count()<=2_000"))

    def test_semantic_call_changes_fail(self) -> None:
        expected = ('"AGENT_TRUST_DOMAIN_PORT"', "8_094", "8_094")
        self.assertFalse(rust_call_contains(
            "router(tokens, authority.clone(), runtime)",
            "router",
            ("authority.clone()", "tokens", "runtime"),
        ))
        self.assertFalse(rust_call_contains(
            'other_i64("AGENT_TRUST_DOMAIN_PORT", 8_094, 8_094)', "required_i64", expected,
        ))
        self.assertFalse(rust_call_contains(
            'required_i64("AGENT_TRUST_DOMAIN_PORT", 8_094, 8_095)', "required_i64", expected,
        ))
        self.assertFalse(rust_call_contains(
            'required_i64("AGENT_TRUST_DOMAIN_PORT", 8_094, 7_000)', "required_i64", expected,
        ))
        self.assertFalse(rust_call_contains(
            'required_i64("AGENT_TRUST_DOMAIN_ PORT", 8_094, 8_094)', "required_i64", expected,
        ))

    def test_comments_do_not_supply_markers(self) -> None:
        commented = """
            // router(authority.clone(), tokens, runtime)
            /* required_i64("AGENT_TRUST_DOMAIN_PORT", 8_094, 8_094) */
            let ready = true;
        """
        self.assertFalse(rust_call_contains(
            commented, "router", ("authority.clone()", "tokens", "runtime"),
        ))
        self.assertFalse(rust_code_contains(commented, "required_i64"))

    def test_comments_between_tokens_are_ignored(self) -> None:
        source = "router(/* authority binding */ authority.clone(), tokens, runtime)"
        self.assertTrue(rust_call_contains(
            source, "router", ("authority.clone()", "tokens", "runtime"),
        ))

    def test_numeric_literals_do_not_absorb_arithmetic_operators(self) -> None:
        self.assertEqual(tokenize_rust("1.0+2"), tokenize_rust("1.0 + 2"))
        self.assertEqual(tokenize_rust("1.0-2"), tokenize_rust("1.0 - 2"))
        self.assertEqual(tokenize_rust("1.0e-2+3"), ("1.0e-2", "+", "3"))
        self.assertEqual(tokenize_rust("0xff_u16 + 1"), ("0xff_u16", "+", "1"))

    def test_large_balanced_json_object_returns_complete_top_level_keys(self) -> None:
        padding = ",\n".join(f'"padding_{index}": {index}' for index in range(220))
        source = f'''json!({{
            "schema_version": READINESS_SCHEMA,
            "nested": {{"nested_only": true, "ready": false}},
            {padding},
            // "comment_only": true,
            "evidence_ready": evidence.ready(),
            "ready": all_ready,
        }})'''
        self.assertGreater(len(source), 2_500)
        key_sets = rust_json_object_key_sets(source)
        self.assertEqual(len(key_sets), 1)
        self.assertIn("schema_version", key_sets[0])
        self.assertIn("ready", key_sets[0])
        self.assertIn("evidence_ready", key_sets[0])
        self.assertIn("padding_219", key_sets[0])
        self.assertNotIn("nested_only", key_sets[0])
        self.assertNotIn("comment_only", key_sets[0])

    def test_function_boundaries_allow_attributes_pub_and_blank_lines(self) -> None:
        source = '''
            #[instrument(skip(state))]
            pub(crate)

            async fn data_ready(state: State<App>) -> Result<Json<Value>, Error> {
                // forbidden_call(secret)
                let note = "forbidden_call(secret)";
                state.ready().await;
                Json(json!({"schema_version": READY, "ready": true}))
            }
            async fn adjacent() { forbidden_call(secret); }
        '''
        functions = extract_rust_functions(source, "data_ready")
        self.assertEqual(len(functions), 1)
        self.assertTrue(rust_function_code_contains(source, "data_ready", "state.ready().await"))
        self.assertTrue(rust_function_call_contains(source, "data_ready", "state.ready", ()))
        self.assertFalse(rust_function_code_contains(source, "data_ready", "forbidden_call(secret)"))
        self.assertFalse(rust_function_call_contains(source, "data_ready", "forbidden_call", ("secret",)))
        self.assertTrue(rust_function_call_contains(source, "adjacent", "forbidden_call", ("secret",)))


if __name__ == "__main__":
    unittest.main()
