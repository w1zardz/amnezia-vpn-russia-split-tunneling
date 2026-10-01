"""Regression tests for replacing managed routes without touching the real Mac."""

from contextlib import ExitStack, redirect_stdout
from copy import deepcopy
import importlib.util
import io
import json
import plistlib
import subprocess
from types import SimpleNamespace
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch


spec = importlib.util.spec_from_file_location(
    "macos_updater", Path(__file__).with_name("update_amnezia_routes.py")
)
updater = importlib.util.module_from_spec(spec)
spec.loader.exec_module(updater)


class ManagedRouteReplacementTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        self.state_dir = root / "state"
        app = root / "AmneziaVPN.app"
        app.mkdir()
        helper = root / "set-amnezia-routes"
        helper.write_text("mock helper; never executed", encoding="utf-8")
        helper.chmod(0o700)
        self.manual = {"manual.example": ["203.0.113.20"]}
        self.preferences = {
            updater.PREFS_ROUTE_KEY: deepcopy(self.manual),
            updater.PREFS_MODE_KEY: updater.ROUTE_MODE_VPN_ALL_EXCEPT_SITES,
            updater.PREFS_ENABLED_KEY: True,
            "Servers.testConfiguration": {"unchanged": True},
        }
        stack = ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(redirect_stdout(io.StringIO()))
        stack.enter_context(patch.object(updater.sys, "platform", "darwin"))
        stack.enter_context(patch.object(updater, "APP_BUNDLE", app))
        stack.enter_context(patch.object(updater, "__file__", str(root / "updater.py")))
        stack.enter_context(patch.object(updater, "verify_app_version", return_value="5.0"))
        stack.enter_context(patch.object(updater, "load_protected_ips"))
        stack.enter_context(patch.object(updater, "warn_broken_ipv6"))
        stack.enter_context(patch.object(
            updater, "export_preferences", side_effect=lambda: (b"", deepcopy(self.preferences))
        ))
        self.inspect = stack.enter_context(patch.object(
            updater, "inspect_amnezia", return_value=updater.AmneziaSession(True, True, True, 2)
        ))
        self.real_stop = updater.stop_amnezia
        self.real_relaunch = updater.relaunch_amnezia
        self.stop = stack.enter_context(patch.object(updater, "stop_amnezia"))
        self.relaunch = stack.enter_context(patch.object(updater, "relaunch_amnezia"))
        self.real_helper = updater.run_helper
        self.helper = stack.enter_context(patch.object(updater, "run_helper", side_effect=self.apply_state))
        self.download = stack.enter_context(patch.object(updater, "download_list"))
        stack.enter_context(patch.object(updater, "process_ids", return_value=[]))
        self.close_clients = stack.enter_context(patch.object(updater, "close_protected_clients"))
        self.check_clients = stack.enter_context(patch.object(updater, "assert_protected_clients_stopped"))

    def apply_state(self, helper_path, state_path):
        state = json.loads(state_path.read_text(encoding="utf-8"))
        for state_key, preference_key in (
            ("sites", updater.PREFS_ROUTE_KEY),
            ("mode", updater.PREFS_MODE_KEY),
            ("enabled", updater.PREFS_ENABLED_KEY),
        ):
            self.preferences[preference_key] = state[state_key]

    def run_update(self, domains, cidrs, with_domains=False, allow_vpn_reconnect=True):
        self.download.return_value = (domains, cidrs)
        self.assertEqual(updater.update(
            state_dir=self.state_dir,
            source="https://example.com/routes.json",
            with_domains=with_domains,
            allow_vpn_reconnect=allow_vpn_reconnect,
        ), 0)

    def read_json(self, filename):
        return json.loads((self.state_dir / filename).read_text(encoding="utf-8"))

    def test_successive_lists_remove_stale_cidrs_and_domains_but_keep_manual_entries(self):
        self.run_update(
            ["old.example", "shared.example"], ["8.8.8.0/24", "1.1.1.0/24"], True
        )
        self.preferences[updater.PREFS_ROUTE_KEY]["shared.example"] = ["203.0.113.31"]
        self.run_update(
            ["shared.example", "new.example"], ["1.1.1.0/24", "9.9.9.0/24"], True
        )
        self.assertEqual(self.preferences[updater.PREFS_ROUTE_KEY], {
            **self.manual,
            "shared.example": ["203.0.113.31"],
            "new.example": [],
            "1.1.1.0/24": [],
            "9.9.9.0/24": [],
        })
        self.assertEqual(self.read_json("managed-cidrs.json"), [
            "shared.example", "new.example", "1.1.1.0/24", "9.9.9.0/24"
        ])

        # Switching to the default IP-only policy also removes previously managed names.
        self.run_update(["ignored.example"], ["9.9.9.0/24", "8.8.4.0/24"])
        self.assertEqual(self.preferences[updater.PREFS_ROUTE_KEY], {
            **self.manual, "9.9.9.0/24": [], "8.8.4.0/24": []
        })
        self.assertEqual(self.read_json("managed-cidrs.json"), ["9.9.9.0/24", "8.8.4.0/24"])
        self.assertEqual(self.read_json("status.json")["manual_entries_preserved"], 1)
        self.assertEqual(self.preferences["Servers.testConfiguration"], {"unchanged": True})

    def test_unchanged_list_does_not_restart_app_or_discard_resolved_values(self):
        self.run_update(["shared.example"], ["1.1.1.0/24"], True)
        self.preferences[updater.PREFS_ROUTE_KEY]["shared.example"] = ["203.0.113.31"]
        before = deepcopy(self.preferences)
        for mock in (self.stop, self.relaunch, self.helper, self.close_clients):
            mock.reset_mock()

        self.run_update(["shared.example"], ["1.1.1.0/24"], True)

        self.assertEqual(self.preferences, before)
        self.assertFalse(self.read_json("status.json")["changed"])
        self.stop.assert_not_called()
        self.relaunch.assert_not_called()
        self.helper.assert_not_called()
        self.close_clients.assert_not_called()

    def test_failed_application_restores_routes_ownership_and_previous_local_list(self):
        self.run_update(["old.example"], ["8.8.8.0/24"], True)
        before_preferences = deepcopy(self.preferences)
        before_files = {path.name: path.read_bytes() for path in self.state_dir.iterdir()}
        for mock in (self.stop, self.relaunch, self.helper, self.close_clients):
            mock.reset_mock()

        def fail_after_first_write(helper_path, state_path):
            self.apply_state(helper_path, state_path)
            if self.helper.call_count == 1:
                raise updater.UpdateError("simulated failure after preference write")

        self.helper.side_effect = fail_after_first_write
        with self.assertRaisesRegex(updater.UpdateError, "simulated failure"):
            self.run_update([], ["9.9.9.0/24"])

        self.assertEqual(self.preferences, before_preferences)
        self.assertEqual(
            {path.name: path.read_bytes() for path in self.state_dir.iterdir()}, before_files
        )
        self.assertEqual(self.helper.call_count, 2)
        self.stop.assert_called_once()
        self.relaunch.assert_called_once()

    def test_local_list_and_state_are_overwritten_without_accumulating_versions(self):
        expected_filenames = {
            "managed-cidrs.json", "amnezia-split-routes.json", "status.json", "update.lock"
        }
        for cidrs in (["8.8.8.0/24", "1.1.1.0/24"], ["9.9.9.0/24"], ["8.8.4.0/24"]):
            with self.subTest(cidrs=cidrs):
                self.run_update([], cidrs)
                self.assertEqual({path.name for path in self.state_dir.iterdir()}, expected_filenames)
                self.assertEqual(self.read_json("managed-cidrs.json"), cidrs)
                self.assertEqual(self.read_json("amnezia-split-routes.json"), [
                    {"hostname": cidr, "ip": ""} for cidr in cidrs
                ])
                status = self.read_json("status.json")
                self.assertEqual(status["entry_count"], len(cidrs))
                self.assertEqual(status["cidr_count"], len(cidrs))
                self.assertEqual(status["manual_entries_preserved"], 1)

    def test_active_vpn_defers_without_changing_applied_files_or_preferences(self):
        self.run_update([], ["8.8.8.0/24"])
        before_preferences = deepcopy(self.preferences)
        before_files = {path.name: path.read_bytes() for path in self.state_dir.iterdir()}
        for mock in (self.stop, self.relaunch, self.helper, self.close_clients):
            mock.reset_mock()

        for session in (
            updater.AmneziaSession(True, True, True, 2),
            updater.AmneziaSession(True, False, True, 2),
            updater.AmneziaSession(False, True, True, 2),
        ):
            with self.subTest(session=session):
                self.inspect.return_value = session
                self.run_update([], ["9.9.9.0/24"], allow_vpn_reconnect=False)
                self.assertEqual(self.preferences, before_preferences)
                for name, contents in before_files.items():
                    self.assertEqual((self.state_dir / name).read_bytes(), contents)
                deferred = self.read_json("deferred-update.json")
                self.assertTrue(deferred["deferred"])
                self.assertEqual(deferred["entries"], ["9.9.9.0/24"])
                self.assertFalse((self.state_dir / updater.PENDING_FILENAME).exists())
                self.stop.assert_not_called()
                self.relaunch.assert_not_called()
                self.helper.assert_not_called()
                self.close_clients.assert_not_called()

    def test_closed_amnezia_applies_default_update_and_clears_deferral(self):
        self.run_update([], ["8.8.8.0/24"], allow_vpn_reconnect=False)
        self.inspect.return_value = updater.AmneziaSession(False, False, True, 2)
        with patch.object(updater, "stop_amnezia", wraps=self.real_stop), \
             patch.object(updater, "relaunch_amnezia", wraps=self.real_relaunch), \
             patch.object(updater, "process_ids", return_value=[]), \
             patch.object(updater.os, "kill") as kill, \
             patch.object(updater.subprocess, "run") as run:
            self.run_update([], ["9.9.9.0/24"], allow_vpn_reconnect=False)
        kill.assert_not_called()
        run.assert_not_called()
        self.assertEqual(self.read_json("managed-cidrs.json"), ["9.9.9.0/24"])
        self.assertFalse((self.state_dir / "deferred-update.json").exists())

    def test_unchanged_list_with_live_vpn_passes_without_permission(self):
        self.run_update([], ["8.8.8.0/24"])
        for mock in (self.stop, self.relaunch, self.helper, self.close_clients):
            mock.reset_mock()
        self.run_update([], ["8.8.8.0/24"], allow_vpn_reconnect=False)
        self.stop.assert_not_called()
        self.relaunch.assert_not_called()
        self.helper.assert_not_called()
        self.close_clients.assert_not_called()

    def test_partial_recovery_cannot_stop_live_vpn_and_keeps_journal(self):
        self.state_dir.mkdir()
        pending_path = self.state_dir / updater.PENDING_FILENAME
        journal = updater.json_bytes({
            "phase": "writing",
            "session": updater.session_document(self.inspect.return_value),
            "previous_managed": [], "desired_managed": ["8.8.8.0/24"],
            "previous_state": {"sites": {}, "mode": 2, "enabled": True},
            "desired_state": {"sites": {"8.8.8.0/24": []}, "mode": 2, "enabled": True},
        })
        pending_path.write_bytes(journal)
        with self.assertRaises(updater.UpdateDeferred):
            updater.recover_pending_transaction(
                Path("unused"), self.state_dir, self.state_dir / "managed-cidrs.json"
            )
        self.assertEqual(pending_path.read_bytes(), journal)
        self.stop.assert_not_called()
        self.relaunch.assert_not_called()
        self.helper.assert_not_called()
        self.close_clients.assert_not_called()

    def test_clients_close_before_journal_and_vpn_stop(self):
        calls = Mock()
        calls.attach_mock(self.close_clients, "close_clients")
        calls.attach_mock(self.stop, "stop")
        calls.attach_mock(self.helper, "helper")

        def close_before_journal(state_dir):
            self.assertEqual(state_dir, self.state_dir)
            self.assertFalse((self.state_dir / updater.PENDING_FILENAME).exists())

        self.close_clients.side_effect = close_before_journal
        self.run_update([], ["8.8.8.0/24"])
        self.assertEqual([call[0] for call in calls.mock_calls[:3]], [
            "close_clients", "stop", "helper"
        ])

    def test_client_refusal_leaves_preferences_untouched_without_transaction(self):
        before = deepcopy(self.preferences)
        self.close_clients.side_effect = updater.UpdateError("client refused")
        with self.assertRaisesRegex(updater.UpdateError, "client refused"):
            self.run_update([], ["8.8.8.0/24"])
        self.assertEqual(self.preferences, before)
        self.assertFalse((self.state_dir / updater.PENDING_FILENAME).exists())
        self.stop.assert_not_called()
        self.helper.assert_not_called()

    def test_reconnect_only_recovery_does_not_close_clients(self):
        self.state_dir.mkdir()
        pending_path = self.state_dir / updater.PENDING_FILENAME
        pending_path.write_bytes(updater.json_bytes({
            "phase": "stopping", "session": updater.session_document(self.inspect.return_value),
        }))
        updater.recover_pending_transaction(
            Path("unused"), self.state_dir, self.state_dir / "managed-cidrs.json"
        )
        self.close_clients.assert_not_called()
        self.relaunch.assert_called_once()

    def test_partial_recovery_closes_clients_before_rollback(self):
        self.state_dir.mkdir()
        self.inspect.return_value = updater.AmneziaSession(False, False, True, 2)
        pending_path = self.state_dir / updater.PENDING_FILENAME
        pending_path.write_bytes(updater.json_bytes({
            "phase": "writing", "session": updater.session_document(self.inspect.return_value),
            "previous_managed": [], "desired_managed": ["8.8.8.0/24"],
            "previous_state": {"sites": {}, "mode": 2, "enabled": True},
            "desired_state": {"sites": {"8.8.8.0/24": []}, "mode": 2, "enabled": True},
        }))
        calls = Mock()
        calls.attach_mock(self.close_clients, "close_clients")
        calls.attach_mock(self.stop, "stop")
        calls.attach_mock(self.helper, "helper")
        updater.recover_pending_transaction(
            Path("unused"), self.state_dir, self.state_dir / "managed-cidrs.json"
        )
        self.assertEqual([call[0] for call in calls.mock_calls[:3]], [
            "close_clients", "stop", "helper"
        ])
        self.assertFalse(pending_path.exists())

    def test_client_start_before_vpn_stop_prevents_signals(self):
        self.check_clients.side_effect = updater.SessionChanged("client started")
        with patch.object(updater, "process_ids", return_value=[123]), \
             patch.object(updater.os, "kill") as kill:
            with self.assertRaisesRegex(updater.SessionChanged, "client started"):
                self.real_stop(updater.AmneziaSession(True, True, True, 2), True)
        kill.assert_not_called()

    def test_client_start_during_write_blocks_further_mutation(self):
        self.check_clients.side_effect = [None, updater.SessionChanged("client started")]
        with patch.object(updater.subprocess, "run") as run:
            run.return_value.returncode = 0
            with self.assertRaisesRegex(updater.SessionChanged, "client started"):
                self.real_helper(Path("test-helper"), Path("test-state"))
        run.assert_called_once()

    def test_stop_guard_and_session_race_prevent_signals(self):
        session = updater.AmneziaSession(True, True, True, 2)
        with patch.object(updater, "stop_amnezia", wraps=self.real_stop) as stop, \
             patch.object(updater, "process_ids", return_value=[123]), \
             patch.object(updater.os, "kill") as kill:
            with self.assertRaises(updater.UpdateDeferred):
                stop(session)
            with self.assertRaises(updater.SessionChanged):
                stop(updater.AmneziaSession(False, False, True, 2))
        kill.assert_not_called()

    def test_gui_start_after_session_check_preserves_recovery_journal(self):
        self.inspect.return_value = updater.AmneziaSession(False, False, True, 2)
        original_preferences = deepcopy(self.preferences)
        # The initial check and stop see an offline session. GUI starts at write time.
        with patch.object(updater, "process_ids", return_value=[123]), \
             patch.object(updater, "run_helper", wraps=self.real_helper), \
             patch.object(updater.subprocess, "run") as run, \
             patch.object(updater.os, "kill") as kill:
            with self.assertRaises(updater.UpdateError):
                self.run_update([], ["9.9.9.0/24"], allow_vpn_reconnect=False)
        self.assertEqual(self.preferences, original_preferences)
        self.assertTrue((self.state_dir / updater.PENDING_FILENAME).exists())
        self.assertFalse((self.state_dir / "status.json").exists())
        kill.assert_not_called()
        run.assert_not_called()

    def test_helper_detects_gui_start_during_write(self):
        with patch.object(updater, "process_ids", side_effect=[[], [], [123]]), \
             patch.object(updater.subprocess, "run") as run:
            run.return_value.returncode = 0
            with self.assertRaises(updater.SessionChanged):
                self.real_helper(Path("test-helper"), Path("test-state"))
        run.assert_called_once()

    def test_gui_start_after_forward_write_blocks_rollback_and_keeps_journal(self):
        self.inspect.return_value = updater.AmneziaSession(False, False, True, 2)

        def race_after_write(helper_path, state_path):
            if self.helper.call_count == 1:
                self.apply_state(helper_path, state_path)
                raise updater.SessionChanged("GUI started during write")
            with patch.object(updater, "process_ids", return_value=[123]):
                self.real_helper(helper_path, state_path)

        self.helper.side_effect = race_after_write
        with self.assertRaisesRegex(updater.UpdateError, "journal сохранён"):
            self.run_update([], ["9.9.9.0/24"], allow_vpn_reconnect=False)
        journal = self.read_json(updater.PENDING_FILENAME)
        self.assertEqual(journal["phase"], "writing")
        self.assertEqual(journal["previous_state"]["sites"], self.manual)
        self.assertEqual(updater.route_state(self.preferences), journal["desired_state"])
        self.assertFalse((self.state_dir / "status.json").exists())


class ProtectedClientClosureTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.state_dir = self.root / "state"
        self.chatgpt = self.make_app("ChatGPT", "com.openai.codex")
        self.claude = self.make_app("Claude", "com.anthropic.claudefordesktop")
        self.current = updater.ClientProcess(100, 1, 501, "/usr/bin/python3")
        stack = ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(patch.object(updater.os, "getuid", return_value=501))
        stack.enter_context(patch.object(updater.os, "getpid", return_value=100))
        stack.enter_context(patch.object(updater, "STATE_DIR", self.state_dir))
        self.start_identity = stack.enter_context(patch.object(
            updater, "client_start_identity", side_effect=lambda pid: (501, 12345, pid)
        ))
        self.real_snapshot = updater.client_process_snapshot
        self.snapshot = stack.enter_context(patch.object(
            updater, "client_process_snapshot", return_value={100: self.current}
        ))
        self.paths = {}
        self.path = stack.enter_context(patch.object(
            updater, "client_executable_path", side_effect=lambda pid: self.paths[pid]
        ))
        self.arguments = stack.enter_context(patch.object(
            updater, "node_process_arguments", return_value=["node", "/tmp/server.js"]
        ))
        stack.enter_context(patch.object(updater, "node_process_directory", return_value=self.root))
        self.run = stack.enter_context(patch.object(
            updater.subprocess, "run", return_value=SimpleNamespace(returncode=0)
        ))
        self.sleep = stack.enter_context(patch.object(updater.time, "sleep"))
        stack.enter_context(patch.object(updater.time, "monotonic", side_effect=[0, 21]))
        self.kill = stack.enter_context(patch.object(updater.os, "kill"))

    def make_app(self, name, bundle_id):
        app = self.root / f"{name}.app"
        (app / "Contents").mkdir(parents=True)
        (app / "Contents/Info.plist").write_bytes(plistlib.dumps({
            "CFBundleIdentifier": bundle_id,
        }))
        return app

    def process(self, pid, app, executable, parent=1, uid=501):
        path = app / "Contents" / executable
        self.paths[pid] = path
        return updater.ClientProcess(pid, parent, uid, str(path))

    def test_success_quits_verified_bundle_and_waits_for_children_without_reopening(self):
        main = self.process(200, self.chatgpt, "MacOS/ChatGPT")
        helper = self.process(201, self.chatgpt, "Resources/node", parent=200)
        self.snapshot.side_effect = [
            {100: self.current, 200: main, 201: helper}, {100: self.current},
        ]
        updater.close_protected_clients()
        self.run.assert_called_once()
        command = self.run.call_args.args[0]
        self.assertEqual(command[:2], ["/usr/bin/osascript", "-e"])
        self.assertEqual(command[2],
            'if application id "com.openai.codex" is running then '
            'tell application id "com.openai.codex" to quit')
        self.kill.assert_not_called()

    def test_orphaned_generic_child_surviving_quit_blocks_update(self):
        main = self.process(200, self.chatgpt, "MacOS/ChatGPT")
        child = updater.ClientProcess(201, 200, 501, "/usr/bin/python3")
        reparented = child._replace(parent_pid=1)
        unrelated = updater.ClientProcess(300, 1, 501, "/usr/bin/node")
        self.paths[300] = Path("/usr/bin/node")
        self.snapshot.side_effect = [
            {100: self.current, 200: main, 201: child, 300: unrelated},
            {100: self.current, 201: reparented, 300: unrelated},
        ]
        with self.assertRaisesRegex(updater.UpdateError, "дочерние процессы"):
            updater.close_protected_clients()
        self.run.assert_called_once()
        self.kill.assert_not_called()

    def test_failed_quit_retry_remembers_orphan_with_start_identity(self):
        main = self.process(200, self.chatgpt, "MacOS/ChatGPT")
        child = updater.ClientProcess(201, 200, 501, "/usr/bin/python3")
        orphan = child._replace(parent_pid=1)
        self.snapshot.side_effect = [
            {100: self.current, 200: main, 201: child}, {100: self.current, 201: orphan},
        ]
        with self.assertRaises(updater.UpdateError):
            updater.close_protected_clients()
        path = self.state_dir / updater.CLIENT_TRACKING_FILENAME
        self.assertEqual(json.loads(path.read_bytes()), [
            {"pid": 201, "uid": 501, "start": [12345, 201]},
        ])
        self.snapshot.side_effect = None
        self.snapshot.return_value = {100: self.current, 201: orphan}
        self.run.reset_mock()
        with patch.object(updater.time, "monotonic", side_effect=[0, 21]):
            with self.assertRaisesRegex(updater.UpdateError, "дочерние процессы"):
                updater.close_protected_clients()
        with self.assertRaises(updater.SessionChanged):
            updater.assert_protected_clients_stopped()
        self.run.assert_not_called()
        self.kill.assert_not_called()
        self.assertEqual([item.name for item in self.state_dir.iterdir()], [path.name])

    def test_reused_pid_does_not_block_unrelated_process(self):
        self.state_dir.mkdir()
        path = self.state_dir / updater.CLIENT_TRACKING_FILENAME
        path.write_bytes(updater.json_bytes([
            {"pid": 201, "uid": 501, "start": [98765, 201]},
        ]))
        unrelated = updater.ClientProcess(201, 1, 501, "/usr/bin/python3")
        self.snapshot.return_value = {100: self.current, 201: unrelated}
        updater.close_protected_clients()
        self.assertFalse(path.exists())
        self.run.assert_not_called()
        self.kill.assert_not_called()

    def test_corrupt_tracking_refuses_without_any_quit(self):
        self.state_dir.mkdir()
        (self.state_dir / updater.CLIENT_TRACKING_FILENAME).write_bytes(b'{"bad": true}')
        with self.assertRaisesRegex(updater.UpdateError, "повреждён список"):
            updater.close_protected_clients()
        self.run.assert_not_called()

    def test_orphaned_app_helper_blocks_update(self):
        helper = self.process(202, self.claude, "Resources/node")
        self.snapshot.return_value = {100: self.current, 202: helper}
        with self.assertRaisesRegex(updater.UpdateError, "ещё работают"):
            updater.close_protected_clients()
        self.kill.assert_not_called()

    def test_cli_refuses_before_quitting_desktop(self):
        main = self.process(200, self.claude, "MacOS/Claude")
        cli = updater.ClientProcess(201, 1, 501, "claude")
        self.snapshot.return_value = {100: self.current, 200: main, 201: cli}
        with self.assertRaisesRegex(updater.UpdateError, "Claude CLI"):
            updater.close_protected_clients()
        self.run.assert_not_called()
        self.kill.assert_not_called()

    def test_unknown_named_client_refuses_before_any_quit(self):
        self.paths[201] = Path("/usr/bin/ChatGPT")
        self.snapshot.return_value = {
            100: self.current, 201: updater.ClientProcess(201, 1, 501, "ChatGPT"),
        }
        with self.assertRaisesRegex(updater.UpdateError, "identity"):
            updater.close_protected_clients()
        self.run.assert_not_called()

    def test_protected_bundle_path_is_matched_by_boundary_not_prefix(self):
        lookalike = self.root / "Claude.app-other/Contents/Resources/node"
        unrelated = updater.ClientProcess(201, 1, 501, str(lookalike))
        self.paths[201] = lookalike
        self.snapshot.return_value = {100: self.current, 201: unrelated}
        updater.close_protected_clients()
        self.assertIsNone(updater.client_bundle_root(lookalike))
        self.run.assert_not_called()

    def test_independent_npm_claude_cli_blocks_all_desktop_quits(self):
        package = self.root / "node_modules/@anthropic-ai/claude-code"
        package.mkdir(parents=True)
        script = package / "cli.js"
        script.write_text("mock CLI", encoding="utf-8")
        (package / "package.json").write_text(json.dumps({
            "name": "@anthropic-ai/claude-code",
        }), encoding="utf-8")
        main = self.process(200, self.chatgpt, "MacOS/ChatGPT")
        node = updater.ClientProcess(201, 1, 501, "/usr/bin/node")
        self.paths[201] = Path("/usr/bin/node")
        self.arguments.return_value = ["node", str(script)]
        self.snapshot.return_value = {100: self.current, 200: main, 201: node}
        with self.assertRaisesRegex(updater.UpdateError, "Claude CLI работает"):
            updater.close_protected_clients()
        self.run.assert_not_called()
        self.kill.assert_not_called()

        preferences = {
            updater.PREFS_ROUTE_KEY: {}, updater.PREFS_MODE_KEY: 2,
            updater.PREFS_ENABLED_KEY: True,
        }
        with patch.object(updater, "export_preferences", return_value=(b"", preferences)), \
             patch.object(updater, "inspect_amnezia", return_value=updater.AmneziaSession(False, False, False, 0)), \
             patch.object(updater, "run_helper") as helper:
            with self.assertRaisesRegex(updater.UpdateError, "Claude CLI работает"):
                updater.apply_preferences(
                    Path("unused"), self.state_dir, self.state_dir / "managed-cidrs.json",
                    [], ["1.1.1.0/24"],
                )
        helper.assert_not_called()
        self.assertFalse((self.state_dir / updater.PENDING_FILENAME).exists())

        self.arguments.return_value = ["node", "node_modules/@anthropic-ai/claude-code/cli.js"]
        with self.assertRaisesRegex(updater.UpdateError, "Claude CLI работает"):
            updater.close_protected_clients()
        self.run.assert_not_called()

        (package / "package.json").unlink()
        with self.assertRaisesRegex(updater.UpdateError, "identity Claude CLI"):
            updater.close_protected_clients()
        self.run.assert_not_called()

    def test_generic_verified_node_does_not_match_or_receive_signal(self):
        self.paths[201] = Path("/usr/bin/node")
        self.snapshot.return_value = {
            100: self.current, 201: updater.ClientProcess(201, 1, 501, "/usr/bin/node"),
        }
        updater.close_protected_clients()
        self.arguments.assert_called_with(201)
        self.run.assert_not_called()
        self.kill.assert_not_called()

    def test_foreign_user_client_is_not_quit(self):
        foreign = self.process(201, self.claude, "MacOS/Claude", uid=502)
        self.snapshot.return_value = {100: self.current, 201: foreign}
        updater.close_protected_clients()
        self.run.assert_not_called()
        self.path.assert_not_called()

    def test_self_ancestor_refuses_before_closing_current_session(self):
        main = self.process(200, self.chatgpt, "MacOS/ChatGPT")
        shell = updater.ClientProcess(201, 200, 501, "/bin/zsh")
        self.snapshot.return_value = {
            100: self.current._replace(parent_pid=201), 200: main, 201: shell,
        }
        with self.assertRaisesRegex(updater.UpdateError, "отдельный Терминал"):
            updater.close_protected_clients()
        self.run.assert_not_called()

    def test_apple_event_error_or_timeout_aborts_without_signals(self):
        main = self.process(200, self.claude, "MacOS/Claude")
        self.snapshot.return_value = {100: self.current, 200: main}
        for effect in (SimpleNamespace(returncode=1), subprocess.TimeoutExpired("osascript", 20)):
            with self.subTest(effect=type(effect).__name__):
                if isinstance(effect, BaseException):
                    self.run.side_effect = effect
                else:
                    self.run.side_effect = None
                    self.run.return_value = effect
                with self.assertRaisesRegex(updater.UpdateError, "закры"):
                    updater.close_protected_clients()
        self.kill.assert_not_called()

    def test_app_restart_at_mutation_boundary_is_refused(self):
        main = self.process(200, self.claude, "MacOS/Claude")
        self.snapshot.return_value = {100: self.current, 200: main}
        with self.assertRaises(updater.SessionChanged):
            updater.assert_protected_clients_stopped()
        self.run.assert_not_called()

    def test_process_snapshot_preserves_spaces_and_rejects_malformed_state(self):
        self.run.return_value = SimpleNamespace(
            returncode=0, stdout="200 1 501 /Applications/Claude.app/Contents/Claude Helper\n",
        )
        processes = self.real_snapshot()
        self.assertEqual(processes[200].command,
                         "/Applications/Claude.app/Contents/Claude Helper")
        self.assertEqual(self.run.call_args.args[0],
                         ["/bin/ps", "-ww", "-axo", "pid=,ppid=,uid=,comm="])
        self.run.return_value.stdout = "malformed\n"
        with self.assertRaises(updater.UpdateError):
            self.real_snapshot()


class SchedulerTests(unittest.TestCase):
    def test_weekly_schedule_has_no_login_or_reconnect_permission(self):
        template_path = Path(__file__).with_name("io.github.amnezia-route-sync.plist.template")
        template = plistlib.loads(template_path.read_bytes())
        self.assertFalse(template["RunAtLoad"])
        self.assertNotIn("StartInterval", template)
        self.assertEqual(template["StartCalendarInterval"], {"Weekday": 0, "Hour": 12, "Minute": 0})
        self.assertNotIn("--allow-vpn-reconnect", template["ProgramArguments"])
        self.assertEqual(template["KeepAlive"]["PathState"], {"__PENDING_PATH__": True})


if __name__ == "__main__":
    unittest.main()
