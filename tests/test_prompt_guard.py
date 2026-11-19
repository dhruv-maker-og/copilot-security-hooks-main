import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from concurrent.futures import ThreadPoolExecutor


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "plugins" / "sensitive-data-guard" / "scripts"
sys.path.insert(0, str(SCRIPTS))
spec = importlib.util.spec_from_file_location("prompt_guard", SCRIPTS / "prompt_guard.py")
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)
EMAIL = "person" + "@" + "example" + ".invalid"
SSN = "-".join(["123", "45", "6789"])
BLOCK_RESPONSE = {
    "decision": "block",
    "reason": "Sensitive data detected. Start a new session without sensitive data.",
}


class PromptGuardTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.environment = patch.dict(os.environ, {"PII_GUARD_STATE_DIR": self.directory.name})
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def event(self, **fields):
        return dict({"sessionId": "synthetic-session", "prompt": "Explain sorting"}, **fields)

    def submit(self, **fields):
        return guard.handle(self.event(**fields), "userPromptSubmitted")

    def tool(self, **fields):
        return guard.handle(self.event(toolArgs={"command": "echo hello"}, **fields), "preToolUse")

    def run_hook(self, event, name, script="prompt_guard.py"):
        env = dict(os.environ, PII_GUARD_EVENT=name, PYTHONDONTWRITEBYTECODE="1")
        return subprocess.run(
            [sys.executable, "-B", str(SCRIPTS / script)],
            input=event if isinstance(event, str) else json.dumps(event),
            capture_output=True, text=True, env=env, check=False,
        )

    def test_tainted_prompt_blocks_clean_tool(self):
        result = self.submit(prompt="Email " + EMAIL)
        self.assertEqual(result, BLOCK_RESPONSE)
        self.assertEqual(self.tool()["permissionDecision"], "deny")

    def test_clean_resubmission_preserves_quarantine(self):
        self.submit(prompt=EMAIL)
        self.assertEqual(self.submit(), BLOCK_RESPONSE)
        self.assertEqual(self.tool()["permissionDecision"], "deny")
        self.submit(sessionId="new-clean-session")
        self.assertEqual(self.tool(sessionId="new-clean-session"), {})

    def test_submit_process_block_and_clean_contracts(self):
        manifest = json.loads((SCRIPTS.parent / "hooks.json").read_text(encoding="utf-8"))
        configured = manifest["hooks"]["UserPromptSubmit"][0]
        self.assertIn("scripts/prompt_guard.py", configured["command"])
        event_name = configured["env"]["PII_GUARD_EVENT"]
        for script, diagnostic in (
            ("prompt_guard.py", "[pii-prompt-guard] Session quarantined; prompt submission blocked.\n"),
            ("check_sensitive_data.py",
             "[sensitive-data-guard] Sensitive prompt data detected; submission blocked.\n"),
        ):
            with self.subTest(script=script):
                event = self.event(session_id=script, hook_event_name="UserPromptSubmit")
                del event["sessionId"]
                clean = self.run_hook(event, event_name, script)
                self.assertEqual(clean.returncode, 0)
                self.assertTrue(json.loads(clean.stdout) == {}, "Unexpected clean response")
                self.assertFalse(clean.stderr, "Unexpected clean diagnostic")
                blocked = self.run_hook(dict(event, prompt="Email " + EMAIL), event_name, script)
                self.assertEqual(blocked.returncode, 0)
                self.assertTrue(json.loads(blocked.stdout) == BLOCK_RESPONSE,
                                "Unexpected block response")
                self.assertTrue(blocked.stderr == diagnostic, "Unexpected block diagnostic")
                if script == "prompt_guard.py":
                    follow_up = self.run_hook(event, event_name, script)
                    self.assertEqual(follow_up.returncode, 0)
                    self.assertTrue(json.loads(follow_up.stdout) == BLOCK_RESPONSE,
                                    "Quarantined session allowed a clean follow-up")
                    self.assertTrue(follow_up.stderr == diagnostic, "Unexpected follow-up diagnostic")
                    state = json.loads(guard.state_path(event).read_text(encoding="utf-8"))
                    self.assertTrue(state == {"tainted": True}, "Unexpected persisted state")

    def test_repeated_pan_prompts_block_both_payload_styles(self):
        pan = "ABCDE" + "1234" + "F"
        for session_key, event_name in (("sessionId", "userPromptSubmitted"),
                                        ("session_id", "UserPromptSubmit")):
            mixed = "".join(char.lower() if index % 2 else char
                            for index, char in enumerate(pan))
            for value in (pan, pan.lower(), mixed, pan):
                with self.subTest(event=event_name):
                    payload = {session_key: event_name, "prompt": "PAN card " + value}
                    result = self.run_hook(payload, event_name)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertTrue(json.loads(result.stdout) == BLOCK_RESPONSE,
                                    "Unexpected block response")
                    tool = self.run_hook(
                        {session_key: event_name, "tool_input": {}}, "preToolUse")
                    self.assertEqual(json.loads(tool.stdout)["permissionDecision"], "deny")
                    transformed = self.run_hook(
                        dict(payload, transformedPrompt=payload["prompt"]),
                        "userPromptTransformed")
                    self.assertEqual(json.loads(transformed.stdout),
                                     {"modifiedTransformedPrompt": "PAN card [REDACTED]"})

    def test_pan_boundaries_and_shape(self):
        pan = "ABCDE" + "1234" + "F"
        for text in ("X" + pan, pan + "X", "ABCD" + "1234" + "F",
                     "ABCDE" + "123" + "F"):
            self.assertFalse(any(label == "PAN Number"
                                 for _, label, _ in guard.scan_text(text)))

    def test_bfsi_case_and_mobile_formats(self):
        cases = {
            "IFSC Code": ["ABCD" + "0" + "123456", "abcd" + "0" + "123456",
                          "AbCd" + "0" + "123456"],
            "Indian Passport Number": ["A" + "1234567", "a" + "1234567"],
            "Indian Mobile Number": ["98765" + "43210", "98765" + " 43210",
                                    "98765" + "-43210", "0" + "98765" + "43210",
                                    "+91 " + "98765" + " 43210",
                                    "987" + "-654-" + "3210"],
        }
        for label, values in cases.items():
            for value in values:
                with self.subTest(label=label, value=value):
                    self.assertTrue(any(found == label
                                        for _, found, _ in guard.scan_text(value)))
                    self.assertEqual(guard.redact(value), "[REDACTED]")

    def test_unicode_variants_redact_original_offsets(self):
        pan = "ABCDE" + "1234" + "F"
        variants = [
            "".join(chr(ord(c) + 0xFEE0) for c in pan),
            "\u200b".join(pan),
            pan[:3] + "\u200d" + pan[3:],
        ]
        for value in variants:
            with self.subTest(value=value):
                self.assertEqual(guard.redact("Before " + value + " after"),
                                 "Before [REDACTED] after")
                self.assertTrue(guard.scan_text(value))

    def test_quoted_json_secrets_are_redacted(self):
        for name in ("password", "passwd", "pwd", "secret", "api_key",
                     "api-secret", "access_token", "client_secret"):
            for quote in ("'", '"'):
                value = quote + name + quote + ": " + quote + "synthetic-only-fixture" + quote
                with self.subTest(name=name, quote=quote):
                    self.assertTrue(guard.scan_text(value))
                    self.assertNotIn("synthetic-only-fixture", guard.redact(value))

    def test_tool_keys_and_numeric_values_are_scanned(self):
        pan = "ABCDE" + "1234" + "F"
        card = int("4111" + "1111" * 3)
        for value in ({pan: "clean"}, {"number": card}, {"nested": [{"number": card}]}):
            with self.subTest(value=value):
                self.submit(sessionId="payload-test")
                result = guard.handle(self.event(sessionId="payload-test", toolArgs=value),
                                      "preToolUse")
                self.assertEqual(result["permissionDecision"], "deny")
                self.assertEqual(self.submit(sessionId="payload-test"), BLOCK_RESPONSE)

    def test_structured_secret_fields_are_scanned(self):
        for value in ({"password": "synthetic-only-fixture"},
                      {"nested": [{"api_key": "synthetic-only-fixture"}]}):
            with self.subTest(value=value):
                result = guard.handle(self.event(toolArgs=value), "preToolUse")
                self.assertEqual(result["permissionDecision"], "deny")

    def test_concurrent_clean_prompts_cannot_clear_quarantine(self):
        pan = "ABCDE" + "1234" + "F"
        prompts = ["Explain sorting"] * 8 + [pan] + ["Explain sorting"] * 8
        with ThreadPoolExecutor(max_workers=4) as executor:
            results = list(executor.map(
                lambda prompt: self.run_hook(self.event(prompt=prompt), "userPromptSubmitted"),
                prompts))
        for result in results:
            self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.tool()["permissionDecision"], "deny")

    def test_abandoned_lock_denies_without_waiting_for_hook_timeout(self):
        target = guard.state_path(self.event())
        target.with_suffix(".lock").mkdir()
        result = self.run_hook(self.event(toolArgs={}), "preToolUse")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stdout)["permissionDecision"], "deny")

    def test_complete_and_unterminated_private_keys_are_redacted(self):
        for kind in ("", "RSA ", "EC ", "OPENSSH ", "PGP "):
            begin = "-----BEGIN " + kind + "PRIVATE KEY-----"
            end = "-----END " + kind + "PRIVATE KEY-----"
            for text in (begin + "\nSYNTHETIC_KEY_BODY\n" + end,
                         begin + "\nSYNTHETIC_KEY_BODY"):
                with self.subTest(kind=kind, terminated=text.endswith(end)):
                    self.assertEqual(guard.redact(text), "[REDACTED]")
        self.assertEqual(guard.redact(begin + "\nfixture\n" + end + " safe"),
                         "[REDACTED] safe")

    def test_bfsi_edge_cases_through_both_hook_contracts(self):
        pan = "ABCDE" + "1234" + "F"
        fixtures = ["abcd" + "0" + "123456", "a" + "1234567",
                    "98765" + " 43210", "\u200b".join(pan),
                    json.dumps({"password": "synthetic-only-fixture"})]
        for key, name in (("sessionId", "userPromptSubmitted"),
                          ("session_id", "UserPromptSubmit")):
            for index, value in enumerate(fixtures):
                with self.subTest(contract=name, fixture=index):
                    payload = {key: name + str(index), "prompt": value}
                    result = self.run_hook(payload, name)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertTrue(json.loads(result.stdout) == BLOCK_RESPONSE,
                                    "Unexpected block response")
                    tool = self.run_hook({key: payload[key], "tool_input": {}}, "PreToolUse")
                    self.assertEqual(json.loads(tool.stdout)["permissionDecision"], "deny")

    def test_sessions_are_isolated(self):
        self.submit(prompt=EMAIL)
        self.submit(sessionId="another-session")
        self.assertEqual(self.tool(sessionId="another-session"), {})
        self.assertEqual(self.tool()["permissionDecision"], "deny")

    def test_missing_state_denies(self):
        self.assertEqual(self.tool()["permissionDecision"], "deny")

    def test_sensitive_tools_denied_in_clean_session(self):
        self.submit()
        for args in ({"nested": [EMAIL]}, json.dumps({"value": SSN}),
                     {"command": "api_key" + "=" + "synthetic_test_value_1234567890"}):
            with self.subTest(args=args):
                result = guard.handle(self.event(toolArgs=args), "preToolUse")
                self.assertEqual(result["permissionDecision"], "deny")
                self.assertNotIn(EMAIL, json.dumps(result))

    def test_snake_case_event_contract(self):
        base = {"session_id": "snake-case-session"}
        result = guard.handle(dict(base, prompt=EMAIL), "UserPromptSubmit")
        self.assertEqual(result, BLOCK_RESPONSE)
        result = guard.handle(dict(base, tool_input={}), "PreToolUse")
        self.assertEqual(result["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_transformed_prompt_redacts_and_taints(self):
        self.submit()
        result = guard.handle(self.event(transformedPrompt="Contact " + EMAIL),
                              "userPromptTransformed")
        self.assertEqual(result, {"modifiedTransformedPrompt": "Contact [REDACTED]"})
        self.assertEqual(self.tool()["permissionDecision"], "deny")

    def test_clean_transformation_preserves_taint(self):
        self.submit(prompt=EMAIL)
        self.assertEqual(guard.handle(self.event(transformedPrompt="Clean text"),
                                      "userPromptTransformed"), {})
        self.assertEqual(self.tool()["permissionDecision"], "deny")

    def test_redaction_checks_checksums_and_overlaps(self):
        self.assertEqual(guard.redact(" ".join(["4111", "1111", "1111", "1111"])),
                         "[REDACTED]")
        invalid = "-".join(["4111", "1111", "1111", "1112"])
        self.assertEqual(guard.redact(invalid), invalid)
        overlapping = "api_key" + "=" + "synthetic-test-person" + "@" + "example.invalid"
        self.assertEqual(guard.redact(overlapping), "[REDACTED]")
        for text in (SSN, "+" + "44 " + "7700 " + "900123",
                     "A" + "1234567", "AKIA" + "A" * 16):
            with self.subTest(text=text):
                self.assertEqual(guard.redact(text), "[REDACTED]")

    def test_session_end_cleanup_idempotent(self):
        self.submit()
        for _ in range(2):
            self.assertEqual(guard.handle(self.event(), "sessionEnd"), {})
        self.assertEqual(list(Path(self.directory.name).iterdir()), [])

    def test_state_contains_no_prompt_or_raw_session(self):
        self.submit(sessionId="../../synthetic", prompt=EMAIL)
        paths = list(Path(self.directory.name).iterdir())
        self.assertEqual(len(paths), 1)
        self.assertEqual(len(paths[0].stem), 64)
        self.assertEqual(json.loads(paths[0].read_text()), {"tainted": True})

    def test_invalid_inputs_fail_visibly(self):
        for payload, name in (("bad json", "preToolUse"), ("[]", "preToolUse"),
                              ({}, "userPromptSubmitted"),
                              (self.event(prompt=None), "userPromptSubmitted"),
                              (self.event(), "unsupported"),
                              (self.event(transformedPrompt=None), "userPromptTransformed")):
            with self.subTest(payload=payload, name=name):
                result = self.run_hook(payload, name)
                self.assertEqual(result.returncode, 2)
                self.assertIn("failure", result.stderr)
                self.assertEqual(json.loads(result.stdout)["permissionDecision"], "deny")
                self.assertNotIn("bad json", result.stderr)

    def test_corrupt_state_denies(self):
        self.submit()
        target = next(Path(self.directory.name).iterdir())
        for contents in ("bad json", "null", '{"tainted":"false"}'):
            target.write_text(contents)
            result = self.run_hook(self.event(toolArgs={}), "preToolUse")
            self.assertEqual(result.returncode, 2)
            self.assertEqual(json.loads(result.stdout)["permissionDecision"], "deny")

    def test_inaccessible_state_denies(self):
        blocker = Path(self.directory.name) / "not-a-directory"
        blocker.write_text("fixture")
        with patch.dict(os.environ, {"PII_GUARD_STATE_DIR": str(blocker)}):
            result = self.run_hook(self.event(toolArgs={}), "preToolUse")
        self.assertEqual(result.returncode, 2)
        self.assertIn("state failure", result.stderr)

    def test_bad_prompt_cannot_reuse_clean_state(self):
        self.submit()
        result = self.run_hook(self.event(prompt=None), "userPromptSubmitted")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(self.tool()["permissionDecision"], "deny")

    def test_bad_transformation_cannot_reuse_clean_state(self):
        self.submit()
        result = self.run_hook(self.event(transformedPrompt=None), "userPromptTransformed")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(self.tool()["permissionDecision"], "deny")

    def test_relative_state_directory_is_rejected(self):
        with patch.dict(os.environ, {"PII_GUARD_STATE_DIR": "relative"}):
            result = self.run_hook(self.event(toolArgs={}), "preToolUse")
        self.assertEqual(result.returncode, 2)

    @unittest.skipUnless(os.name == "nt", "Windows manifest command execution")
    def test_installed_plugin_commands_with_spaces(self):
        installed = Path(self.directory.name) / "installed plugin" / "scripts"
        installed.mkdir(parents=True)
        for name in ("prompt_guard.py", "check_sensitive_data.py"):
            shutil.copyfile(SCRIPTS / name, installed / name)
        manifest = json.loads((ROOT / "plugins/sensitive-data-guard/hooks.json").read_text())
        payloads = {
            "UserPromptSubmit": self.event(),
            "PreToolUse": self.event(tool_input={}),
            "userPromptTransformed": self.event(transformedPrompt="Explain sorting"),
            "SessionEnd": self.event(),
        }
        for name in ("UserPromptSubmit", "userPromptTransformed", "PreToolUse", "SessionEnd"):
            item = manifest["hooks"][name][0]
            for platform in ("windows", "powershell"):
                command = item[platform].replace("${PLUGIN_ROOT}", str(installed.parent))
                result = subprocess.run(
                    ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
                    input=json.dumps(payloads[name]), capture_output=True, text=True,
                    env=dict(os.environ, **item["env"], PYTHONDONTWRITEBYTECODE="1"),
                    cwd=self.directory.name, check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout), {})

    def test_subprocess_lifecycle(self):
        for name, fields, expected in (
            ("userPromptSubmitted", {"prompt": EMAIL}, "decision"),
            ("userPromptTransformed", {"transformedPrompt": EMAIL},
             "modifiedTransformedPrompt"),
            ("preToolUse", {"toolArgs": {}}, "permissionDecision"),
            ("sessionEnd", {}, None),
        ):
            result = self.run_hook(self.event(**fields), name)
            self.assertEqual(result.returncode, 0, result.stderr)
            output = json.loads(result.stdout)
            if expected:
                self.assertIn(expected, output)
            else:
                self.assertEqual(output, {})

    def test_slash_command_body_is_scanned(self):
        workspace = Path(self.directory.name) / "workspace"
        prompts = workspace / ".github" / "prompts"
        prompts.mkdir(parents=True)
        (prompts / "fixture.prompt.md").write_text("---\nname: fixture\n---\n" + EMAIL)
        self.assertEqual(self.submit(prompt="/fixture", cwd=str(workspace)), BLOCK_RESPONSE)

    def test_manifests_and_versions(self):
        for target in ROOT.rglob("*.json"):
            json.loads(target.read_text(encoding="utf-8"))
        plugin = json.loads((ROOT / "plugins/sensitive-data-guard/plugin.json").read_text())
        catalog = json.loads((ROOT / ".github/plugin/marketplace.json").read_text())
        self.assertEqual(plugin["version"], catalog["plugins"][0]["version"])


if __name__ == "__main__":
    unittest.main()
