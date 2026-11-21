# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Richard Bejtlich
"""sf-patch-day tests. Run: python -I tests/test_sf_patch_day.py

Every DLL and plugin here is made up by tests/makers.py. The function checks use sf-pex-tools' own made-up test
archive; they need sf-pex-tools (SF_PEX_TOOLS, or a sf-pex-tools folder next to this repo) and skip without it.
"""
import argparse
import contextlib
import io
import json
import os
import re
import shutil
import struct
import sys
import tempfile
import unittest
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

import makers as mk  # noqa: E402
from sf_patch_day import cli, dlls, drift, pe, pextools, scripts  # noqa: E402
from sf_patch_day.plugin import Plugin  # noqa: E402

V244, V300 = mk.game_version(1, 16, 244), mk.game_version(1, 16, 300)


def run(*argv):
    """(exit code, stdout text) of the command line, run in this process."""
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
        try:
            code = cli.main(list(argv))
        except SystemExit as e:
            code = e.code
    return code, out.getvalue()


def write(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)


class Temp(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="sf-patch-day-test-")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def p(self, *parts):
        return os.path.join(self.tmp, *parts)


# ---- the PE reader --------------------------------------------------------------------------------------------
class TestPE(unittest.TestCase):
    def test_block_round_trip(self):
        data = mk.sfse_plugin(name="Alpha", author="Someone", plugin_version=0x15070000, address=4, structure=8,
                              compatible=[V244], sfse_required=mk.game_version(0, 2, 21))
        b = pe.sfse_block(data)
        self.assertEqual((b["name"], b["author"], b["address"], b["structure"]), ("Alpha", "Someone", 4, 8))
        self.assertEqual(b["compatible"], [V244])
        self.assertEqual(pe.version_text(b["sfse_required"]), "0.2.21")
        self.assertEqual(pe.plugin_version_text(b["plugin_version"]), "21.7.0")
        self.assertEqual(pe.plugin_version_text(2), "2")

    def test_no_export_and_junk(self):
        self.assertIsNone(pe.sfse_block(mk.pe_file()))
        self.assertIsNone(pe.sfse_block(mk.pe_file(b"SomethingElse", b"x" * 16)))
        with self.assertRaises(pe.PEError):
            pe.sfse_block(b"not a program at all" * 10)
        with self.assertRaises(pe.PEError):
            pe.sfse_block(mk.sfse_plugin()[:0x500])  # cut short

    def test_file_version(self):
        self.assertEqual(pe.PE(mk.pe_file(file_version=(1, 16, 300, 0))).file_version(), (1, 16, 300, 0))
        self.assertIsNone(pe.PE(mk.pe_file()).file_version())

    def test_address_library_hint(self):
        self.assertTrue(pe.mentions_address_library(b"..versionlib-{}.bin.."))
        self.assertTrue(pe.mentions_address_library("Data\\SFSE\\Plugins\\versionlib".encode("utf-16-le")))
        self.assertFalse(pe.mentions_address_library(b"nothing here"))


# ---- the verdict rule -------------------------------------------------------------------------------------------
class TestVerdict(unittest.TestCase):
    T = (1, 16, 300)

    def v(self, al=True, sfse=None, **kw):
        return dlls.verdict(pe.sfse_block(mk.sfse_plugin(**kw)), self.T, al, sfse)[0]

    def test_rules(self):
        self.assertEqual(self.v(compatible=[V244]), dlls.LOCKED)
        self.assertEqual(self.v(compatible=[V300]), dlls.WORKS)
        self.assertEqual(self.v(address=4, structure=8), dlls.WORKS)
        self.assertEqual(self.v(al=False, address=4, structure=8), dlls.NEEDS_AL)
        self.assertEqual(self.v(al=False, address=4, structure=8, compatible=[V300]), dlls.NEEDS_AL)
        self.assertEqual(self.v(address=1, structure=1), dlls.MAY_FAIL)
        self.assertEqual(self.v(address=4, structure=0, compatible=[V244]), dlls.LOCKED)  # no structure promise
        self.assertEqual(self.v(address=2, structure=8, compatible=[V244]), dlls.LOCKED)  # old Address Library only
        self.assertEqual(self.v(address=4, structure=8, reserved_breaking=1), dlls.LOCKED)
        self.assertEqual(self.v(data_version=2, address=4, structure=8), dlls.LOCKED)
        self.assertEqual(self.v(sfse=mk.game_version(0, 2, 21), sfse_required=mk.game_version(0, 2, 30),
                                compatible=[V300]), dlls.NEEDS_SFSE)
        self.assertEqual(dlls.verdict(None, self.T, True)[0], dlls.NOT_SFSE)

    def test_parse_game_version(self):
        self.assertEqual(dlls.parse_game_version("1.16.244"), (1, 16, 244))
        self.assertEqual(dlls.parse_game_version("1.16.244.0"), (1, 16, 244))
        self.assertIsNone(dlls.parse_game_version("latest"))


# ---- dlls on a made-up game folder ------------------------------------------------------------------------------
class TestDllsCommand(Temp):
    def make_game(self, with_sfse=True, with_al=False):
        game = self.p("Starfield")
        write(os.path.join(game, "Starfield.exe"), mk.pe_file(file_version=(1, 16, 300, 0)))
        if with_sfse:
            write(os.path.join(game, "sfse_1_16_300.dll"), mk.pe_file(file_version=(0, 0, 2, 30)))
        plugins = os.path.join(game, "Data", "SFSE", "Plugins")
        write(os.path.join(plugins, "Locked.dll"), mk.sfse_plugin(name="Locked", compatible=[V244]))
        write(os.path.join(plugins, "Listed.dll"), mk.sfse_plugin(name="Listed", compatible=[V244, V300]))
        write(os.path.join(plugins, "UsesAL.dll"), mk.sfse_plugin(name="UsesAL", address=4, structure=8,
                                                                   extra=b"versionlib-{}.bin"))
        write(os.path.join(plugins, "Scans.dll"), mk.sfse_plugin(name="Scans", address=1, structure=1))
        write(os.path.join(plugins, "Helper.dll"), mk.pe_file())
        write(os.path.join(plugins, "Broken.dll"), b"MZ" + b"\xff" * 100)
        if with_al:
            write(os.path.join(plugins, "versionlib-1-16-300-0.bin"), b"made-up")
        return game

    def report(self, *argv):
        code, out = run("dlls", "--json", *argv)
        return code, json.loads(out)

    def verdicts(self, rep):
        return {r["file"]: r["verdict"] for r in rep["plugins"]}

    def test_patch_day(self):
        game = self.make_game()
        code, rep = self.report("--game", game)
        self.assertEqual(rep["game_version"], "1.16.300")
        self.assertEqual(pe.version_text(rep["sfse"]["sfse_version"]), "0.2.30")
        self.assertEqual(self.verdicts(rep), {"Locked.dll": dlls.LOCKED, "Listed.dll": dlls.WORKS,
                                              "UsesAL.dll": dlls.NEEDS_AL, "Scans.dll": dlls.MAY_FAIL,
                                              "Helper.dll": dlls.NOT_SFSE, "Broken.dll": dlls.UNREADABLE})
        self.assertEqual(code, 3)  # Broken.dll is unreadable
        os.remove(os.path.join(game, "Data", "SFSE", "Plugins", "Broken.dll"))
        self.assertEqual(self.report("--game", game)[0], 2)  # Locked.dll

    def test_address_library_arrives(self):
        game = self.make_game(with_al=True)
        for f in ("Broken.dll", "Locked.dll"):
            os.remove(os.path.join(game, "Data", "SFSE", "Plugins", f))
        code, rep = self.report("--game", game)
        self.assertEqual(self.verdicts(rep)["UsesAL.dll"], dlls.WORKS)
        self.assertEqual(code, 1)  # Scans.dll may fail
        os.remove(os.path.join(game, "Data", "SFSE", "Plugins", "Scans.dll"))
        self.assertEqual(self.report("--game", game)[0], 0)

    def test_no_sfse_for_version(self):
        game = self.make_game(with_sfse=False, with_al=True)
        for f in ("Broken.dll", "Locked.dll", "Scans.dll"):
            os.remove(os.path.join(game, "Data", "SFSE", "Plugins", f))
        code, rep = self.report("--game", game)
        self.assertFalse(rep["sfse"]["sfse_found"])
        self.assertEqual(code, 1)
        code, out = run("dlls", "--game", game)
        self.assertIn("SFSE: NOT FOUND", out)

    def test_zip_and_version_override(self):
        game = self.make_game(with_al=True)
        z = self.p("download.zip")
        with zipfile.ZipFile(z, "w") as zf:
            zf.writestr("SFSE/Plugins/NewMod.dll", mk.sfse_plugin(name="NewMod", address=4, structure=8))
            zf.writestr("readme.txt", "made up")
        code, rep = self.report(z, "--game", game)
        self.assertEqual(self.verdicts(rep), {"download.zip :: SFSE/Plugins/NewMod.dll": dlls.WORKS})
        self.assertEqual(code, 0)  # the game's Address Library file counts; its DLLs aren't judged
        code, rep = self.report(z, "--game-version", "1.16.400")
        self.assertEqual(self.verdicts(rep), {"download.zip :: SFSE/Plugins/NewMod.dll": dlls.NEEDS_AL})

    def test_text_report_and_log(self):
        game = self.make_game()
        logf = self.p("run.log")
        code, out = run("dlls", "--game", game, "--log", logf)
        self.assertIn("Game version: 1.16.300", out)
        self.assertIn("LOCKED", out)
        self.assertIn("what to do:", out)
        with open(logf, encoding="utf-8") as f:
            text = f.read()
        self.assertIn("[dlls]", text)
        self.assertIn("Locked.dll", text)

    def test_one_bad_zip_member_is_only_that_file(self):
        game = self.make_game(with_al=True)
        z = self.p("mixed.zip")
        with zipfile.ZipFile(z, "w") as zf:
            zf.writestr("Locked/Secret.dll", mk.sfse_plugin(name="Secret"))
            zf.writestr("Good.dll", mk.sfse_plugin(name="Good", address=4, structure=8))
        # Mark the first member "encrypted" (bit 0 of its flags, in the local and central headers): reading it then
        # raises RuntimeError, as a password-protected download does.
        with open(z, "rb") as f:
            data = bytearray(f.read())
        data[6] |= 1
        central = data.index(b"PK\x01\x02")
        data[central + 8] |= 1
        with open(z, "wb") as f:
            f.write(data)
        code, rep = self.report(z, "--game", game)
        self.assertEqual(self.verdicts(rep), {"mixed.zip :: Locked/Secret.dll": dlls.UNREADABLE,
                                              "mixed.zip :: Good.dll": dlls.WORKS})
        self.assertEqual(code, 3)

    def test_unreadable_folder_is_reported(self):
        folder = self.p("Plugins")
        os.makedirs(folder)
        real_walk = dlls.os.walk

        def walk(path, onerror=None):
            onerror(PermissionError(13, "Access is denied", path))
            return iter(())
        dlls.os.walk = walk
        try:
            items, _al, problems = dlls.collect([folder])
        finally:
            dlls.os.walk = real_walk
        self.assertEqual(items, [])
        self.assertEqual(len(problems), 1)
        self.assertIn("Access is denied", problems[0][1])

    def test_hint(self):
        path = self.p("Quiet.dll")
        write(path, mk.sfse_plugin(name="Quiet", address=1, structure=1, extra="versionlib".encode("utf-16-le")))
        r = dlls.judge(dlls.Item("Quiet.dll", path), (1, 16, 300), False, None)
        self.assertEqual(r["verdict"], dlls.MAY_FAIL)
        self.assertIn("names an Address Library file", r["hint"])

    def test_game_pass_and_errors(self):
        game = self.make_game(with_sfse=False)
        write(os.path.join(game, "appxmanifest.xml"), b"<made-up/>")
        code, out = run("dlls", "--game", game)
        self.assertIn("SFSE: this is a Game Pass install, and SFSE doesn't support Game Pass", out)
        self.assertEqual(code, 3)  # Broken.dll; without it, Game Pass alone gives 2
        os.remove(os.path.join(game, "Data", "SFSE", "Plugins", "Broken.dll"))
        code, out = run("dlls", "--game", game)
        self.assertEqual(code, 2)
        self.assertIn("don't load on the Game Pass version, and some are locked", out)
        only_helpers = self.p("helpers")
        write(os.path.join(only_helpers, "Helper.dll"), mk.pe_file())
        # No SFSE plugin checked: nothing waits for an update, and on Game Pass the missing SFSE isn't news.
        code, out = run("dlls", only_helpers, "--game", game)
        self.assertEqual(code, 0, out)
        self.assertEqual(out.count("Game Pass install"), 1, out)  # said once
        self.assertNotIn("waits for an SFSE update", out)
        self.assertEqual(run("dlls", "--game", self.p("nowhere"))[0], 3)
        self.assertEqual(run("dlls", self.p("x.zip"), "--game-version", "soon")[0], 3)
        self.assertEqual(run("dlls", self.p("missing.dll"), "--game-version", "1.16.300")[0], 3)
        self.assertEqual(run("dlls", "--no-such-option")[0], 3)


# ---- drift ------------------------------------------------------------------------------------------------------
def master_esm(stages=(10, 20), conditions=(1, 2), glob_value=1.0, compress=False, extra_quest=False):
    quests = [mk.quest(0x01000800, "TM_Quest", stages, compress=compress)]
    if extra_quest:
        quests.append(mk.quest(0x01000900, "TM_NewQuest", [5]))
    return mk.plugin(0x1, ["Starfield.esm"], [
        mk.group("QUST", quests),
        mk.group("CNDF", [mk.cndf(0x01000801, "TM_Start", conditions)]),
        mk.group("GLOB", [mk.glob(0x01000802, "TM_Glob", glob_value)]),
    ])


class TestDrift(Temp):
    def setUp(self):
        super().setUp()
        self.data = self.p("Data")
        write(self.p("Data", "Starfield.esm"), mk.plugin(0x1))
        write(self.p("Data", "TestMaster.esm"), master_esm())
        write(self.p("Data", "LightMaster.esm"), mk.plugin(0x101, ["Starfield.esm"],
                                                           [mk.group("GLOB", [mk.glob(0x01000801, "LM_Glob", 0)])]))
        self.mods = self.p("mods.json")
        with open(self.mods, "w", encoding="utf-8") as f:
            json.dump({"mod": "TestMod.esm", "masters": {"TestMaster.esm": {"records": [
                {"edid": "TM_Start", "copied": True, "why": "made-up start conditions"},
                {"edid": "TM_Quest", "stages": [10]}]}}}, f)
        self.base = self.p("baseline.json")

    def snap(self):
        self.assertEqual(run("drift", "snapshot", "--mods", self.mods, "-o", self.base, "--data", self.data)[0], 0)

    def check(self):
        return run("drift", "check", "--mods", self.mods, "--baseline", self.base, "--data", self.data)

    def test_unchanged(self):
        self.snap()
        code, out = self.check()
        self.assertEqual(code, 0, out)
        self.assertIn("RESULT: no change", out)

    def test_change_not_used(self):
        self.snap()
        write(self.p("Data", "TestMaster.esm"), master_esm(glob_value=2.0, extra_quest=True))
        code, out = self.check()
        self.assertEqual(code, 1, out)
        self.assertIn("UPDATED", out)

    def test_copied_record_changed(self):
        self.snap()
        write(self.p("Data", "TestMaster.esm"), master_esm(conditions=(1, 3)))
        code, out = self.check()
        self.assertEqual(code, 2, out)
        self.assertIn("TM_Start: CHANGED", out)

    def test_stage_gone_and_compressed(self):
        self.snap()
        write(self.p("Data", "TestMaster.esm"), master_esm(stages=(20, 30), compress=True))
        code, out = self.check()
        self.assertEqual(code, 2, out)
        self.assertIn("stage 10 is GONE", out)

    def test_record_gone(self):
        self.snap()
        write(self.p("Data", "TestMaster.esm"), mk.plugin(0x1, ["Starfield.esm"], [mk.group("QUST", [
            mk.quest(0x01000800, "TM_Quest", [10, 20])])]))
        code, out = self.check()
        self.assertEqual(code, 2, out)
        self.assertIn("TM_Start: GONE", out)

    def test_master_missing_and_bad_files(self):
        self.snap()
        os.remove(self.p("Data", "TestMaster.esm"))
        code, out = self.check()
        self.assertEqual(code, 3, out)
        self.assertIn("--plugin-dir", out)
        with open(self.mods, "w", encoding="utf-8") as f:
            f.write('{"masters": {"Data/TestMaster.esm": {"records": [{"stages": "ten"}]}}}')
        code, out = self.check()
        self.assertEqual(code, 3)
        self.assertIn("doesn't follow the mods file format", out)
        with open(self.mods, "w", encoding="utf-8") as f:
            f.write("{not json")
        self.assertIn("isn't valid JSON", self.check()[1])

    def test_plugin_dir_first(self):
        mm = self.p("MO2", "mods", "Test Master")
        write(os.path.join(mm, "TestMaster.esm"), master_esm(conditions=(9,)))
        self.snap()
        code, out = run("drift", "check", "--mods", self.mods, "--baseline", self.base, "--data", self.data,
                        "--plugin-dir", mm)
        self.assertEqual(code, 2, out)  # the mod manager's copy is read first, and it differs

    def test_never_writes_in_game_folder(self):
        game = self.p("Game")
        write(os.path.join(game, "Starfield.exe"), mk.pe_file(file_version=(1, 16, 300, 0)))
        write(os.path.join(game, "Data", "TestMaster.esm"), master_esm())
        code, out = run("drift", "snapshot", "--mods", self.mods, "-o", os.path.join(game, "b.json"), "--data",
                        os.path.join(game, "Data"))
        self.assertEqual(code, 3)
        self.assertIn("never writes there", out)
        self.assertFalse(os.path.exists(os.path.join(game, "b.json")))

    def test_init(self):
        mod = self.p("src", "TestMod.esm")
        write(mod, mk.plugin(0x1, ["Starfield.esm", "TestMaster.esm", "LightMaster.esm"], [
            mk.group("CNDF", [mk.cndf(0x01000801, "TM_Start", [1])]),         # override of TestMaster's record
            mk.group("GLOB", [mk.glob(0xFE000801, "LM_Glob", 5)]),            # override in a light master
            mk.group("KYWD", [mk.record("KYWD", 0x02000800, [mk.edid("TMod_Own")])]),  # the mod's own record
            mk.group("CELL", [mk.record("REFR", 0x01000999, [])]),            # a placed reference, no Editor ID
        ]))
        out_file = self.p("src", "mods.json")
        code, out = run("drift", "init", mod, "-o", out_file, "--data", self.data)
        self.assertEqual(code, 0, out)
        with open(out_file, encoding="utf-8") as f:
            m = json.load(f)
        self.assertEqual([r["edid"] for r in m["masters"]["TestMaster.esm"]["records"]], ["TM_Start"])
        self.assertEqual([r["edid"] for r in m["masters"]["LightMaster.esm"]["records"]], ["LM_Glob"])
        self.assertIn("1 REFR", out)
        self.assertEqual(run("drift", "init", mod, "-o", out_file, "--data", self.data)[0], 3)  # exists, no --force
        # The written file is a valid mods file, and every record has a type (fast scanning).
        self.assertEqual(drift.validate_mods(m), [])
        self.assertEqual(schema_problems(m), [])
        self.snap()

    def test_init_with_nothing_to_watch(self):
        # Found in the 0.1.3 clean-folder test: a plugin with only its own records gives an empty mods file. init
        # must say snapshot needs an entry first, and snapshot's refusal must name the cause, not a format error.
        mod = self.p("src", "OwnOnly.esm")
        write(mod, mk.plugin(0x1, ["Starfield.esm"],
                             [mk.group("KYWD", [mk.record("KYWD", 0x01000800, [mk.edid("Own_Kw")])])]))
        out_file = self.p("src", "mods.json")
        code, out = run("drift", "init", mod, "-o", out_file, "--data", self.data)
        self.assertEqual(code, 0, out)
        self.assertIn("has nothing to watch yet", out)
        self.assertNotIn("Next: add the quest stages", out)  # not the line that sends you straight to snapshot
        code, out = run("drift", "snapshot", "--mods", out_file, "-o", self.base, "--data", self.data)
        self.assertEqual(code, 3)
        self.assertIn('"masters" is empty, so there is nothing to watch', out)
        self.assertFalse(os.path.exists(self.base))
        # A file with no "masters" at all keeps the format message.
        self.assertIn("at least one plugin", drift.validate_mods({"mod": "x.esm"})[0])

    def test_fingerprint(self):
        code, out = run("fingerprint", "TestMaster.esm", "--data", self.data)
        self.assertEqual(code, 0, out)
        self.assertIn("probe FormID 000802", out)  # the GLOB is the highest own probe-type record
        with Plugin(self.p("Data", "LightMaster.esm"), [self.data]) as p:
            self.assertEqual(p.mask, 0xFFF)

    def test_stage_never_there_is_a_note(self):
        with open(self.mods, "w", encoding="utf-8") as f:
            json.dump({"masters": {"TestMaster.esm": {"records": [{"edid": "TM_Quest", "stages": [10, 99]}]}}}, f)
        code, out = run("drift", "snapshot", "--mods", self.mods, "-o", self.base, "--data", self.data)
        self.assertEqual(code, 0, out)
        self.assertIn("not found (check the name): TM_Quest stage 99", out)  # said at snapshot time, too
        write(self.p("Data", "TestMaster.esm"), master_esm(glob_value=2.0))
        code, out = self.check()
        self.assertEqual(code, 1, out)
        self.assertIn("stage 99 not found now or in the baseline", out)

    def test_lower_case_type_and_used_by(self):
        with open(self.mods, "w", encoding="utf-8") as f:
            json.dump({"masters": {"TestMaster.esm": {"used_by": ["MyMod"], "records": [
                {"edid": "tm_quest", "type": "qust"}]}}}, f)
        self.snap()
        with open(self.base, encoding="utf-8") as f:
            self.assertIsNotNone(json.load(f)["masters"]["TestMaster.esm"]["records"]["tm_quest"])
        with open(self.mods, "w", encoding="utf-8") as f:
            json.dump({"masters": {"TestMaster.esm": {"used_by": "MyMod", "records": []}}}, f)
        code, out = self.check()
        self.assertEqual(code, 3)
        self.assertIn("used_by must be a list", out)

    def test_snapshot_keeps_the_old_baseline(self):
        self.snap()
        code, out = run("drift", "snapshot", "--mods", self.mods, "-o", self.base, "--data", self.data)
        self.assertEqual(code, 3)
        self.assertIn("--force", out)
        self.assertEqual(run("drift", "snapshot", "--mods", self.mods, "-o", self.base, "--data", self.data,
                             "--force")[0], 0)

    def test_damaged_record(self):
        for size_field in (b"\x01\x00", b"\x01\x00\x00\x00\x00\x00"):  # too short and too long
            write(self.p("Data", "TestMaster.esm"), mk.plugin(0x1, ["Starfield.esm"], [mk.group("CNDF", [
                mk.record("CNDF", 0x01000801, [mk.edid("TM_Start"), mk.sub("XXXX", size_field)])])]))
            code, out = run("drift", "snapshot", "--mods", self.mods, "-o", self.base, "--data", self.data)
            self.assertEqual(code, 3, out)
            self.assertIn("TM_Start", out)
            self.assertIn("damaged XXXX", out)
            self.assertNotIn("unexpected error", out)

    def test_damaged_header_names_the_file(self):
        bad = mk.record("TES4", 0, [mk.sub("HEDR", bytes(12)), mk.sub("XXXX", b"\x01\x00")], flags=1)
        write(self.p("Data", "TestMaster.esm"), bad)
        code, out = run("drift", "snapshot", "--mods", self.mods, "-o", self.base, "--data", self.data)
        self.assertEqual(code, 3, out)
        self.assertIn("TestMaster.esm: a record has a damaged XXXX", out)
        write(self.p("Data", "TestMaster.esm"), b"just some text, not a plugin")
        code, out = run("drift", "snapshot", "--mods", self.mods, "-o", self.base, "--data", self.data)
        self.assertEqual(code, 3, out)
        self.assertIn("not a Starfield plugin", out)
        self.assertEqual(out.count("TestMaster.esm"), 1, out)  # the path is named once

    def test_file_names_ignore_case(self):
        from sf_patch_day import plugin as plugin_module
        folder = self.p("CaseTest")
        write(os.path.join(folder, "foo.ESM"), mk.plugin(0x1))
        plugin_module.clear_cache()
        found = plugin_module.find_plugin("Foo.esm", [folder])
        self.assertIsNotNone(found)
        self.assertEqual(os.path.basename(found).lower(), "foo.esm")
        exact = os.path.join(folder, "Bar.esm")
        write(exact, mk.plugin(0x1))
        self.assertEqual(plugin_module.find_plugin("Bar.esm", [folder]), exact)  # the exact name comes first
        self.assertIsNone(plugin_module.find_plugin("Missing.esm", [folder]))

    def test_case_fallback_on_a_case_sensitive_system(self):
        """Runs the fallback on any system: the file checks and the folder listing act as on Linux, where
        Foo.ESM and foo.ESM are two files and neither is Foo.esm."""
        from unittest import mock
        from sf_patch_day import log, plugin as plugin_module
        folder = os.path.abspath(self.p("CaseSensitive"))
        os.makedirs(folder)
        logf = self.p("case.log")
        log.setup(False, logf)  # opened before the file functions are replaced
        stored = {"foo.ESM", "Foo.ESM", "Bar.esm", "bar.ESM"}
        real_isfile, real_listdir = os.path.isfile, os.listdir
        fail_once = [True]

        def isfile(p):
            if os.path.normcase(os.path.dirname(p)) == os.path.normcase(folder):
                return os.path.basename(p) in stored
            return real_isfile(p)

        def listdir(d):
            if os.path.normcase(os.path.abspath(d)) == os.path.normcase(folder):
                if fail_once[0]:
                    fail_once[0] = False
                    raise PermissionError(13, "Access is denied", d)
                return sorted(stored)
            return real_listdir(d)
        key = os.path.normcase(folder)
        try:
            with mock.patch.object(plugin_module.os.path, "isfile", isfile), \
                    mock.patch.object(plugin_module.os, "listdir", listdir):
                plugin_module.clear_cache()
                self.assertIsNone(plugin_module.find_plugin("foo.esm", [folder]))  # the listing failed this once
                self.assertNotIn(key, plugin_module._INDEX)                         # and the failure isn't kept
                found = plugin_module.find_plugin("foo.esm", [folder + os.sep])     # the next lookup lists again
                self.assertEqual(os.path.basename(found), "Foo.ESM")                 # sorted: same pick every run
                self.assertIn(key, plugin_module._INDEX)
                plugin_module.find_plugin("foo.esm", [folder])                      # said once, not twice
                # An exact hit warns too when another copy differs only in case.
                self.assertEqual(plugin_module.find_plugin("Bar.esm", [folder]), os.path.join(folder, "Bar.esm"))
                warnings = plugin_module.warnings()
        finally:
            plugin_module.clear_cache()
            log.close()
        self.assertEqual(len(warnings), 2, warnings)
        self.assertIn("foo.ESM", warnings[0])
        self.assertIn("bar.ESM", warnings[1])
        self.assertIn("may load a different one", warnings[1])
        with open(logf, encoding="utf-8") as f:
            text = f.read()
        self.assertIn("can't list", text)
        self.assertEqual(text.count("WARNING:"), 2, text)

    def test_bare_plugin_name_uses_the_current_folder(self):
        from sf_patch_day import plugin as plugin_module
        folder = self.p("BareName")
        # The master isn't there, so the lookup lists the plugin's own folder: for a bare name that is "", which
        # must mean the current folder (listing "" fails).
        write(os.path.join(folder, "Mod.esm"), mk.plugin(0x1, ["Starfield.esm"]))
        logf = self.p("bare.log")
        here = os.getcwd()
        os.chdir(folder)
        try:
            code, out = run("fingerprint", "Mod.esm", "--log", logf)
        finally:
            os.chdir(here)
            plugin_module.clear_cache()
        self.assertEqual(code, 0, out)
        with open(logf, encoding="utf-8") as f:
            self.assertNotIn("can't list", f.read())

    def test_failed_run_still_shows_the_copies_warning(self):
        """A damaged plugin with a second copy that differs only in case (as on Linux): init and check fail, and
        the warning that may explain it is shown, with --json too."""
        from unittest import mock
        from sf_patch_day import plugin as plugin_module
        folder = os.path.abspath(self.p("Copies"))
        damaged = os.path.join(folder, "Mod.esm")
        write(damaged, b"damaged")
        real_isfile = os.path.isfile

        def index(f):
            return {"mod.esm": ["Mod.esm", "mod.ESM"]} if os.path.normcase(f) == os.path.normcase(folder) else {}

        def isfile(p):
            if os.path.normcase(os.path.dirname(p)) == os.path.normcase(folder):
                return os.path.basename(p) in ("Mod.esm", "mod.ESM")
            return real_isfile(p)
        with mock.patch.object(plugin_module, "_folder_index", index), \
                mock.patch.object(plugin_module.os.path, "isfile", isfile):
            code, out = run("drift", "init", damaged, "-o", self.p("m.json"), "--data", self.data)
            self.assertEqual(code, 3, out)
            self.assertIn("WARNING:", out)
            self.assertIn("RESULT: CANNOT CHECK", out)
            with open(self.mods, "w", encoding="utf-8") as f:
                json.dump({"masters": {"Mod.esm": {"records": []}}}, f)
            code, out = run("drift", "check", "--mods", self.mods, "--baseline", self.p("none.json"),
                            "--data", folder, "--json")
            self.assertEqual(code, 3, out)
            self.assertIn("WARNING:", out)
        # The --json setting never carries into a later run, also when a run stops early (an unwritable log).
        code, out = run("dlls", "--json", "--game-version", "1.16.300", self.p("nothing.dll"))
        self.assertEqual((code, json.loads(out)["exit"]), (3, 3))  # a JSON report that says exit 3
        self.assertFalse(cli._JSON[0])
        code, out = run("dlls", "--json", "--game-version", "1.16.300", "--log", self.p("no-such-folder", "x.log"))
        self.assertEqual(code, 3, out)
        self.assertIn("can't write the log file", out)  # the early stop, in plain text
        self.assertFalse(cli._JSON[0])
        # The next run without --json in the same process prints its text report, not JSON.
        code, out = run("dlls", "--game-version", "1.16.300", self.p("nothing.dll"))
        self.assertEqual(code, 3, out)
        self.assertIn("RESULT:", out)
        with self.assertRaises(ValueError):
            json.loads(out)

    def test_no_command_and_failed_log_setup(self):
        def run_err(*argv):
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = cli.main(list(argv))
            return code, out.getvalue(), err.getvalue()
        code, out, err = run_err()
        self.assertEqual(code, 3)
        self.assertIn("usage:", out)  # the help
        self.assertIn("RESULT: CANNOT CHECK: no command given", err)
        code, out, err = run_err("dlls", "--verbose", "--game-version", "1.16.300",
                                 "--log", self.p("no-such-folder", "x.log"))
        self.assertEqual(code, 3)
        self.assertIn("can't write the log file", out)
        self.assertNotIn("[end]", err)  # the log never opened, so it has no last line
        # drift without a step: help and a RESULT line on stderr, not an "unexpected error".
        code, out, err = run_err("drift")
        self.assertEqual(code, 3)
        self.assertIn("usage:", out)
        self.assertIn("RESULT: CANNOT CHECK: no drift step given", err)
        self.assertNotIn("unexpected error", out + err)
        # cmd_drift handles a bare "drift" itself too, without relying on main() to stop it first.
        args = cli.build_parser().parse_args(["drift"])
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.cmd_drift(args)
        self.assertEqual(code, 3)
        self.assertIn("usage:", out.getvalue())
        self.assertIn("RESULT: CANNOT CHECK: no drift step given", err.getvalue())
        # A hand-built Namespace with no "cmd" still gets the drift message, not "no command given".
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.cmd_drift(argparse.Namespace(drift_cmd=None))
        self.assertEqual(code, 3)
        self.assertIn("no drift step given", err.getvalue())
        # A run that stops on an error ends its log with that exit code, not "done".
        code, out, err = run_err("fingerprint", "x.esm", "--verbose", "--data", self.p("nowhere"))
        self.assertEqual(code, 3)
        self.assertIn("[end] exit code 3", err)

    def test_result_wording(self):
        self.assertEqual(drift.result([(drift.OK, "x")])[0], 0)
        code, res = drift.result([(drift.OK, "x"), (drift.WARN, "copies")])
        self.assertEqual(code, 1)
        self.assertIn("no change found, but see the WARN line", res)  # nothing changed: it mustn't say so
        code, res = drift.result([(drift.NOTE, "x"), (drift.WARN, "copies")])
        self.assertIn("NOTE lines", res)
        self.assertIn("also see the WARN line", res)  # the RESULT line alone tells the whole story
        self.assertIn("also see the WARN line", drift.result([(drift.SKIP, "x"), (drift.WARN, "copies")])[1])
        self.assertEqual(drift.result([(drift.ACTION, "x"), (drift.WARN, "copies")])[0], 2)

    def test_names_listed_twice(self):
        with open(self.mods, "w", encoding="utf-8") as f:
            json.dump({"masters": {"TestMaster.esm": {"records": [{"edid": "TM_Quest"}, {"edid": "tm_quest"}]},
                                   "testmaster.esm": {"records": []}}}, f)
        code, out = self.check()
        self.assertEqual(code, 3)
        self.assertIn('"testmaster.esm" is listed twice', out)
        self.assertIn('record "tm_quest" is listed twice', out)

    def test_name_case_fixed_after_snapshot(self):
        with open(self.mods, "w", encoding="utf-8") as f:
            json.dump({"masters": {"testmaster.esm": {"records": [{"edid": "tm_start", "copied": True}]}}}, f)
        self.snap()
        with open(self.mods, "w", encoding="utf-8") as f:
            json.dump({"masters": {"TestMaster.esm": {"records": [{"edid": "TM_Start", "copied": True}]}}}, f)
        write(self.p("Data", "TestMaster.esm"), master_esm(conditions=(1, 3)))
        code, out = self.check()
        self.assertEqual(code, 2, out)  # the change is still found under the corrected spelling
        self.assertIn("TM_Start: CHANGED", out)

    def test_skip_without_pex_tools(self):
        mods = drift.load_mods(self.mods)
        mods["masters"]["TestMaster.esm"]["ba2"] = "TestMaster - Main.ba2"
        mods["masters"]["TestMaster.esm"]["functions"] = {"scripts/X.pex": ["DoIt"]}
        base = drift.take(mods, [self.data], None, "sf-pex-tools not found")
        lines = drift.compare(base, base, mods)
        self.assertIn(drift.SKIP, [lv for lv, _ in lines])
        self.assertEqual(drift.result(lines)[0], 1)


TOOLS, _ = pextools.find(None)


@unittest.skipIf(TOOLS is None, "sf-pex-tools not found (set SF_PEX_TOOLS)")
class TestDriftFunctions(Temp):
    def test_functions(self):
        data = self.p("Data")
        write(os.path.join(data, "TestMaster.esm"), master_esm())
        shutil.copy(os.path.join(TOOLS.folder, "tests", "fixtures", "a1.ba2"), os.path.join(data, "TestMaster - Main.ba2"))
        mods, base = self.p("mods.json"), self.p("base.json")
        with open(mods, "w", encoding="utf-8") as f:
            json.dump({"masters": {"TestMaster.esm": {"ba2": "TestMaster - Main.ba2", "records": [], "functions": {
                "Scripts/SfPexToolsTest/Alpha.pex": ["AddMission", "Score", "trycount", "NoSuchFunction"],
                "scripts/SfPexToolsTest/Gone.pex": ["Nothing"]}}}}, f)
        code, out = run("drift", "snapshot", "--mods", mods, "-o", base, "--data", data, "--pex-tools", TOOLS.folder)
        self.assertEqual(code, 0, out)
        self.assertIn('scripts not found (check the path and the "ba2" archive name): '
                      'scripts/SfPexToolsTest/Gone.pex', out)
        self.assertIn("function NoSuchFunction()", out)  # a likely typo, said at snapshot time
        with open(base, encoding="utf-8") as f:
            b = json.load(f)
        funcs = b["masters"]["TestMaster.esm"]["functions"]
        # trycount matches TryCount: Papyrus names ignore case.
        self.assertEqual(funcs["Scripts/SfPexToolsTest/Alpha.pex"], {"AddMission": 2, "Score": 3, "trycount": 0})
        self.assertIsNone(funcs["scripts/SfPexToolsTest/Gone.pex"])
        code, out = run("drift", "check", "--mods", mods, "--baseline", base, "--data", data,
                        "--pex-tools", TOOLS.folder)
        self.assertEqual(code, 1, out)  # missing now and in the baseline: check the name, not a rebuild
        self.assertIn("NoSuchFunction() not found now or in the baseline", out)
        self.assertIn("Gone.pex: not in", out)
        # Pretend the update changed Score's arguments, and the archive lost a script and a function.
        funcs["Scripts/SfPexToolsTest/Alpha.pex"]["Score"] = 2
        funcs["Scripts/SfPexToolsTest/Alpha.pex"]["NoSuchFunction"] = 1
        funcs["scripts/SfPexToolsTest/Gone.pex"] = {"Nothing": 0}
        with open(base, "w", encoding="utf-8") as f:
            json.dump(b, f)
        code, out = run("drift", "check", "--mods", mods, "--baseline", base, "--data", data,
                        "--pex-tools", TOOLS.folder)
        self.assertEqual(code, 2, out)
        self.assertIn("Score() now takes 3 arguments (was 2)", out)
        self.assertIn("function NoSuchFunction() is GONE", out)
        self.assertIn("Gone.pex: script GONE", out)
        self.assertEqual(run("drift", "check", "--mods", mods, "--baseline", base, "--data", data,
                             "--pex-tools", self.p("nowhere"))[0], 3)


# ---- drift init reads the mod's scripts --------------------------------------------------------------------------
class TestScriptParts(Temp):
    """The parts of the script reader that don't need sf-pex-tools."""

    def test_split_args(self):
        self.assertEqual(scripts.split_args("ident:SetStage, ident:q, ident:::t1, int:10"),
                         ["ident:SetStage", "ident:q", "ident:::t1", "int:10"])
        # A comma or quote inside a string doesn't split it.
        self.assertEqual(scripts.split_args("ident:x, str:'a, b', str:\"it's, ok\", None"),
                         ["ident:x", "str:'a, b'", "str:\"it's, ok\"", "None"])
        self.assertEqual(scripts.split_args(""), [])

    def test_vmad(self):
        field = mk.vmad([("SM:QuestScript", [
            ("TargetQuest", 1, 0x01000800), ("Label", 2, "x"), ("StageProp", 3, 20), ("Rate", 4, 1.5),
            ("On", 5, True), ("Pair", 7, [("A", 1, 0x01000801), ("B", 3, 2)]), ("Many", 11, [1, 2]),
            ("Names", 12, ["a", "b"]), ("Rows", 17, [[("C", 3, 1)], [("C", 3, 2)]]), ("After", 1, 0x02000801)]),
            ("Second", [("Q", 1, 7)])], tail=b"\x02\x00\x00")  # quest fragment data after the scripts is left alone
        found = scripts.vmad_scripts(field[6:])
        self.assertEqual(found, [("SM:QuestScript", {"targetquest": ("obj", 0x01000800), "stageprop": ("int", 20),
                                                     "after": ("obj", 0x02000801)}),
                                 ("Second", {"q": ("obj", 7)})])
        with self.assertRaises(scripts.ScriptError):
            scripts.vmad_scripts(field[6:][:20])  # cut off

    def test_vmad_variable_properties(self):
        # Type 6 (Variable) has no value bytes and 16 (array of Variable) only a count, as xEdit reads them; the
        # record's other properties are still read.
        field = mk.vmad([("SM:S", [("V", 6, None), ("Vs", 16, 0), ("After", 1, 0x01000800), ("N", 3, 5)])])
        self.assertEqual(scripts.vmad_scripts(field[6:]), [("SM:S", {"after": ("obj", 0x01000800), "n": ("int", 5)})])

    def test_vmad_quest_tail(self):
        tail = mk.quest_tail("Fragments:Quests:QF_A", [("Q", 1, 0x01000800), ("Many", 16, 0)],
                             fragments=[(10, "Fragments:Quests:QF_A", "Fragment_Stage_0010")],
                             aliases=[(0, [("SM:AliasScript", [("Q", 1, 0x01000801)])]), (1, [])])
        field = mk.vmad([("SM:QuestScript", [])], tail=tail)
        attached, extra, problem = scripts.vmad_parts(field[6:], "QUST")
        self.assertEqual(attached, [("SM:QuestScript", {})])
        self.assertEqual(extra, [("Fragments:Quests:QF_A", {"q": ("obj", 0x01000800)}, "fragment"),
                                 ("Fragments:Quests:QF_A", {}, "fragment"),
                                 ("SM:AliasScript", {"q": ("obj", 0x01000801)}, "alias")])
        self.assertIsNone(problem)
        # A damaged tail keeps the attached scripts and says why.
        attached, extra, problem = scripts.vmad_parts(field[6:-3], "QUST")
        self.assertEqual((attached, extra), ([("SM:QuestScript", {})], []))
        self.assertIn("ends early", problem)
        # No tail, and record types without a fragment section: nothing more.
        self.assertEqual(scripts.vmad_parts(mk.vmad([("A", [])])[6:], "QUST")[1:], ([], None))
        self.assertEqual(scripts.vmad_parts(field[6:], "ACTI")[1:], ([], None))

    def test_vmad_fragment_tails_of_other_records(self):
        # INFO, PACK, SCEN, PERK and TMLM: the fragment script entry is read by the same helper as a quest's. With a
        # name it has a status byte and properties. With an empty name, Mutagen writes the name only (as a quest's
        # fragment script always is) and xEdit reads a full entry: both layouts are read and end at the field's end.
        frags = [("TIF_A", "Fragment_Begin"), ("TIF_B", "Fragment_End")]
        for sig in ("INFO", "PACK", "SCEN", "PERK", "TMLM"):
            phases = [("SF_Phase", "Fragment_Phase_01")] if sig == "SCEN" else []
            names = [(n, {}, "fragment") for n, _ in frags + phases]
            for case, kw, want in (
                    ("named", {"script": "Fragments:X", "props": [("Q", 1, 0x01000800)]},
                     [("Fragments:X", {"q": ("obj", 0x01000800)}, "fragment")] + names),
                    ("empty, Mutagen", {}, names),
                    ("empty, xEdit", {"full_empty": True}, names)):
                with self.subTest(sig=sig, case=case):
                    tail = mk.fragment_tail(sig, fragments=frags, phases=phases, **kw)
                    field = mk.vmad([("SM:Attached", [])], tail=tail)[6:]
                    self.assertEqual(scripts.vmad_parts(field, sig), ([("SM:Attached", {})], want, None))
        # A quest alias script with an empty name, as Mutagen writes it: the alias after it is still read.
        tail = (b"\x03" + struct.pack("<H", 0) + mk._wstr("") + struct.pack("<H", 2)
                + struct.pack("<HhI", 0, 0, 0) + struct.pack("<HHH", 6, 2, 1) + mk._wstr("")
                + struct.pack("<HhI", 0, 1, 0) + struct.pack("<HHH", 6, 2, 1) + mk.script_entry("SM:AliasB", []))
        field = mk.vmad([], tail=tail)[6:]
        self.assertEqual(scripts.vmad_parts(field, "QUST"), ([], [("SM:AliasB", {}, "alias")], None))

    def test_fragment_layout_order_per_record_type(self):
        # A quest tries the name-only layout first; here its empty alias entry is a full one (as xEdit reads it),
        # followed by a named alias: the name-only reading doesn't fit, the full one does.
        alias = struct.pack("<HhI", 0, 0, 0) + struct.pack("<HHH", 6, 2, 1)
        tail = (b"\x03" + struct.pack("<H", 0) + mk._wstr("") + struct.pack("<H", 2)
                + alias + mk.script_entry("", []) + alias + mk.script_entry("SM:AliasB", []))
        self.assertEqual(scripts.vmad_parts(mk.vmad([], tail=tail)[6:], "QUST"), ([], [("SM:AliasB", {}, "alias")],
                                                                                   None))
        # PERK and TMLM try xEdit's full entry first. With a byte too many at the end neither layout ends at the
        # field's end; the preferred (full) reading is kept, which finds the fragment (name-only finds none).
        for sig in ("PERK", "TMLM"):
            with self.subTest(sig):
                tail = mk.fragment_tail(sig, fragments=[("TIF_A", "Fragment_A")], full_empty=True) + b"\x00"
                self.assertEqual(scripts.vmad_parts(mk.vmad([], tail=tail)[6:], sig),
                                 ([], [("TIF_A", {}, "fragment")], None))

    def test_console_archives_left_out(self):
        d = self.p("d")
        write(os.path.join(d, "MyMod - Main.ba2"), mk.ba2([]))
        write(os.path.join(d, "MyMod - Main_xbox.ba2"), mk.ba2([]))
        write(os.path.join(d, "MyMod - Main_PS5.ba2"), mk.ba2([]))
        self.assertEqual([os.path.basename(p) for p in scripts.own_archives("MyMod", [d])], ["MyMod - Main.ba2"])
        os.remove(os.path.join(d, "MyMod - Main.ba2"))  # only console archives: read them
        self.assertEqual([os.path.basename(p) for p in scripts.own_archives("MyMod", [d])],
                         ["MyMod - Main_PS5.ba2", "MyMod - Main_xbox.ba2"])

    def test_own_archives(self):
        d = self.p("d")
        write(os.path.join(d, "MyMod - Main.ba2"), mk.ba2([("scripts/a.pex", b"x")]))
        write(os.path.join(d, "MyMod - Textures.ba2"), b"BTDX\x01\x00\x00\x00DX10" + bytes(12))  # textures: no scripts
        write(os.path.join(d, "MyMod - Part - Main.ba2"), mk.ba2([]))  # belongs to "MyMod - Part.esm"
        write(os.path.join(d, "MyModOther - Main.ba2"), mk.ba2([]))
        self.assertEqual([os.path.basename(p) for p in scripts.own_archives("MyMod", [d])], ["MyMod - Main.ba2"])
        self.assertEqual([os.path.basename(p) for p in scripts.own_archives("mymod - part", [d])],
                         ["MyMod - Part - Main.ba2"])

    def test_init_without_pex_tools(self):
        data, mod = self.p("Data"), self.p("src", "ScriptMod.esm")
        write(os.path.join(data, "Starfield.esm"), mk.plugin(0x1))
        write(os.path.join(data, "TestMaster.esm"), master_esm())
        write(mod, mk.plugin(0x1, ["Starfield.esm", "TestMaster.esm"], [
            mk.group("QUST", [mk.record("QUST", 0x02000800, [mk.edid("SM_Quest"),
                                                             mk.vmad([("SM:QuestScript", [])])])])]))
        mods, notes, summary = drift.init(mod, [data], None, "sf-pex-tools not found (install it)")
        self.assertEqual(mods["masters"], {})  # as in 0.1.3: only overrides, and there are none
        self.assertTrue(any(n.startswith("scripts not read: sf-pex-tools not found (install it)") for n in notes),
                        notes)
        self.assertIsNone(summary["scripts"])


def script_mod(root, data):
    """A made-up mod in root (ScriptMod.esm, its archive and a loose script) whose scripts call functions of
    sf-pex-tools' made-up test scripts (in TestMaster - Main.ba2) and set stages of TestMaster.esm's TM_Quest."""
    write(os.path.join(data, "Starfield.esm"), mk.plugin(0x1))
    write(os.path.join(data, "TestMaster.esm"), master_esm(stages=(10, 20, 30)))
    shutil.copy(os.path.join(TOOLS.folder, "tests", "fixtures", "a1.ba2"), os.path.join(data, "TestMaster - Main.ba2"))
    quest = mk.pex("SM:QuestScript", "Quest",
                   variables=[("::TargetQuest_var", "Quest"), ("::StageProp_var", "Int"),
                              ("Helper", "SfPexToolsTest:Alpha"), ("Kid", "SM:Kid")],
                   properties=[("TargetQuest", "Quest", "::TargetQuest_var"), ("StageProp", "Int", "::StageProp_var")],
                   functions=[
                       ("Run", [], [("::t1", "Bool"), ("::t2", "Int"), ("::t3", "Float"), ("::t4", "String"),
                                    ("::nonevar", "None")], [
                           ("callmethod", ["ident:SetStage", "ident:::TargetQuest_var", "ident:::t1", "int:10"]),
                           ("callmethod", ["ident:Step", "ident:self", "ident:::nonevar", "ident:::TargetQuest_var",
                                           "ident:::StageProp_var"]),
                           ("callmethod", ["ident:AddMission", "ident:Helper", "ident:::t2", "str:a, b", "int:5"]),
                           ("callmethod", ["ident:score", "ident:Helper", "ident:::t3", "int:1"]),  # 1 of 3 arguments
                           ("callstatic", ["ident:SfPexToolsTest:Beta", "ident:Describe", "ident:::t4"]),
                           ("callmethod", ["ident:Vanished", "ident:Helper", "ident:::nonevar"]),
                           ("callmethod", ["ident:Note", "ident:Kid", "ident:::nonevar", "str:x"])]),
                       ("Step", [("akQuest", "Quest"), ("aiStage", "Int")], [("::t1", "Bool")], [
                           ("callmethod", ["ident:SetStage", "ident:akQuest", "ident:::t1", "ident:aiStage"])])])
    kid = mk.pex("SM:Kid", "SfPexToolsTest:Beta", functions=[
        ("Note", [("asName", "String")], [("::nonevar", "None"), ("::t1", "String")], [
            ("callparent", ["ident:Note", "ident:::nonevar", "ident:asName"]),
            ("callmethod", ["ident:Describe", "ident:self", "ident:::t1"])])])
    selfq = mk.pex("SM:SelfScript", "Quest", functions=[
        ("Go", [], [("::t1", "Bool"), ("x", "Int")], [
            ("callmethod", ["ident:SetStage", "ident:self", "ident:::t1", "int:20"]),
            ("callmethod", ["ident:SetCurrentStageID", "ident:self", "ident:::t1", "ident:x"])])])  # not known
    write(os.path.join(root, "ScriptMod - Main.ba2"), mk.ba2([("scripts/SM/QuestScript.pex", quest)]))
    write(os.path.join(root, "Scripts", "SM", "Kid.pex"), kid)  # loose, reached through QuestScript's variable
    write(os.path.join(root, "Scripts", "SM", "SelfScript.pex"), selfq)  # loose, attached to the override
    mod = os.path.join(root, "ScriptMod.esm")
    write(mod, mk.plugin(0x1, ["Starfield.esm", "TestMaster.esm"], [
        mk.group("QUST", [
            mk.record("QUST", 0x02000800, [mk.edid("SM_Quest"), mk.vmad([("SM:QuestScript", [
                ("TargetQuest", 1, 0x01000800), ("StageProp", 3, 30)])], tail=mk.quest_tail())]),
            # An override of TM_Quest with the mod's script attached: SetStage on self is TM_Quest.
            mk.record("QUST", 0x01000800, [mk.edid("TM_Quest"), mk.vmad([("SM:SelfScript", [])])])])]))
    return mod


def schema_problems(doc, schema=None, where="$"):
    """The ways doc breaks examples/mods.schema.json, checked with the parts of JSON Schema that file uses (the
    standard library has no JSON Schema checker)."""
    if schema is None:
        with open(os.path.join(os.path.dirname(HERE), "examples", "mods.schema.json"), encoding="utf-8") as f:
            schema = json.load(f)
    kinds = {"object": dict, "array": list, "string": str, "boolean": bool}
    t = schema.get("type")
    if t == "integer":
        if not isinstance(doc, int) or isinstance(doc, bool):
            return [f"{where}: not an integer"]
    elif t and not isinstance(doc, kinds[t]):
        return [f"{where}: not {t}"]
    p = []
    if isinstance(doc, (int, float)) and not isinstance(doc, bool):
        if doc < schema.get("minimum", doc) or doc > schema.get("maximum", doc):
            p.append(f"{where}: {doc} out of range")
    if isinstance(doc, str) and not schema.get("minLength", 0) <= len(doc) <= schema.get("maxLength", len(doc)):
        p.append(f"{where}: length {len(doc)}")
    if isinstance(doc, dict):
        p += [f"{where}: {k} missing" for k in schema.get("required", []) if k not in doc]
        if len(doc) < schema.get("minProperties", 0):
            p.append(f"{where}: too few entries")
        pattern = schema.get("propertyNames", {}).get("pattern")
        for k, v in doc.items():
            if pattern and not re.search(pattern, k):
                p.append(f"{where}: name {k!r} doesn't match {pattern}")
            sub = schema.get("properties", {}).get(k, schema.get("additionalProperties", {}))
            p += schema_problems(v, sub if isinstance(sub, dict) else {}, f"{where}.{k}")
    if isinstance(doc, list) and "items" in schema:
        for i, v in enumerate(doc):
            p += schema_problems(v, schema["items"], f"{where}[{i}]")
    return p


class TestSchema(unittest.TestCase):
    def test_example_and_checker(self):
        with open(os.path.join(os.path.dirname(HERE), "examples", "mods.example.json"), encoding="utf-8") as f:
            self.assertEqual(schema_problems(json.load(f)), [])
        self.assertTrue(schema_problems({"masters": {"bad/name.esm": {"records": [{"type": "QUSTX"}]}}}))


@unittest.skipIf(TOOLS is None, "sf-pex-tools not found (set SF_PEX_TOOLS)")
class TestInitScripts(Temp):
    def test_init_reads_scripts(self):
        data, src = self.p("Data"), self.p("src")
        mod = script_mod(src, data)
        out_file = self.p("mods.json")
        code, out = run("drift", "init", mod, "-o", out_file, "--data", data, "--pex-tools", TOOLS.folder)
        self.assertEqual(code, 0, out)
        with open(out_file, encoding="utf-8") as f:
            m = json.load(f)
        self.assertEqual(drift.validate_mods(m), [])
        self.assertEqual(schema_problems(m), [])
        self.assertEqual(list(m["masters"]), ["TestMaster.esm"])
        tm = m["masters"]["TestMaster.esm"]
        self.assertEqual(tm["ba2"], "TestMaster - Main.ba2")
        self.assertEqual(tm["functions"], {"scripts/sfpextoolstest/alpha.pex": ["AddMission", "Score"],
                                           "scripts/sfpextoolstest/beta.pex": ["Describe", "Note"]})
        # One record: the override, marked copied, with the stages both scripts set (10 constant, 30 from the Int
        # property through Step, 20 on self). SetCurrentStageID(x) can't be known before the game runs.
        self.assertEqual(len(tm["records"]), 1, tm["records"])
        rec = tm["records"][0]
        self.assertEqual((rec["edid"], rec["type"], rec["copied"], rec["stages"]), ("TM_Quest", "QUST", True, [10, 20, 30]))
        self.assertIn("SM:QuestScript, SM:SelfScript", rec["why"])
        self.assertIn("isn't listed", rec["why"])
        self.assertIn("Score() with 1 argument(s), but the installed TestMaster.esm script takes 3", out)
        self.assertIn("SfPexToolsTest:Alpha.Vanished(), which no master script defines now", out)
        self.assertIn("read 3 of your mod's own script(s)", out)
        self.assertNotIn("note: the fragment or alias scripts", out)
        # The file works with snapshot and check: every stage and function is found.
        base = self.p("base.json")
        code, out = run("drift", "snapshot", "--mods", out_file, "-o", base, "--data", data, "--pex-tools", TOOLS.folder)
        self.assertEqual(code, 0, out)
        self.assertNotIn("not found (check the name)", out)
        self.assertIn("4 function(s)", out)
        code, out = run("drift", "check", "--mods", out_file, "--baseline", base, "--data", data,
                        "--pex-tools", TOOLS.folder)
        self.assertEqual(code, 0, out)
        # The same input gives the same file, byte for byte.
        again = self.p("again.json")
        self.assertEqual(run("drift", "init", mod, "-o", again, "--data", data, "--pex-tools", TOOLS.folder)[0], 0)
        with open(out_file, "rb") as a, open(again, "rb") as b:
            self.assertEqual(a.read(), b.read())

    def test_new_quest_record_and_bad_pex(self):
        # A quest the mod doesn't override gets its own record; a damaged script is a note, not a failure.
        data, src = self.p("Data"), self.p("src")
        script_mod(src, data)
        selfq = mk.pex("SM:Setter", "Quest", variables=[("::Q_var", "Quest")], properties=[("Q", "Quest", "::Q_var")],
                       functions=[("Go", [], [("::t1", "Bool")], [
                           ("callmethod", ["ident:SetStage", "ident:::Q_var", "ident:::t1", "int:10"])])])
        write(os.path.join(src, "Scripts", "SM", "Setter.pex"), selfq)
        write(os.path.join(src, "Scripts", "SM", "Broken.pex"), b"\xde\xc0\x57\xfa damaged")
        mod = os.path.join(src, "Other.esm")
        write(mod, mk.plugin(0x1, ["Starfield.esm", "TestMaster.esm"], [mk.group("QUST", [
            mk.record("QUST", 0x02000800, [mk.edid("OT_Quest"), mk.vmad([("SM:Setter", [("Q", 1, 0x01000800)]),
                                                                           ("SM:Broken", [])])])])]))
        mods, notes, summary = drift.init(mod, [data], TOOLS)
        rec = mods["masters"]["TestMaster.esm"]["records"]
        self.assertEqual(rec, [{"edid": "TM_Quest", "type": "QUST", "why": "Stages set by script SM:Setter",
                                "stages": [10]}])
        self.assertEqual(summary["quests"], 1)
        self.assertTrue(any("couldn't read scripts/SM/Broken.pex" in n for n in notes), notes)

    def test_pex_tools_given_but_missing(self):
        data, src = self.p("Data"), self.p("src")
        mod = script_mod(src, data)
        code, out = run("drift", "init", mod, "-o", self.p("m.json"), "--data", data, "--pex-tools", self.p("nowhere"))
        self.assertEqual(code, 3)
        self.assertIn("ba2_extract.py and pex_compare.py aren't there", out)
        self.assertFalse(os.path.exists(self.p("m.json")))


def tm_world(data):
    """Starfield.esm, TestMaster.esm (TM_Quest, stages 10 20 30) and TestMaster - Main.ba2 holding the made-up
    scripts TM:Base (Hello()) and TM:Api extends TM:Base (Ping(aiValue), Pong())."""
    write(os.path.join(data, "Starfield.esm"), mk.plugin(0x1))
    write(os.path.join(data, "TestMaster.esm"), master_esm(stages=(10, 20, 30)))
    write(os.path.join(data, "TestMaster - Main.ba2"), mk.ba2([
        ("scripts/TM/Base.pex", tm_base()),
        ("scripts/TM/Api.pex", mk.pex("TM:Api", "TM:Base", functions=[("Ping", [("aiValue", "Int")], [], []),
                                                                       ("Pong", [], [], [])]))]))


def tm_base():
    return mk.pex("TM:Base", "ScriptObject", functions=[("Hello", [], [], [])])


def calls(name, parent, *targets, variables=(), properties=(), code=()):
    """A made-up script whose Run() makes the static calls targets [(type, function, [args])] and runs code."""
    return mk.pex(name, parent, variables=variables, properties=properties, functions=[
        ("Run", [], [("::t", "None")], [("callstatic", [f"ident:{t}", f"ident:{f}", "ident:::t"] + list(a))
                                        for t, f, a in targets] + list(code))])


def init_lines(out):
    return [x for x in out.splitlines() if x.startswith("note:")]


@unittest.skipIf(TOOLS is None, "sf-pex-tools not found (set SF_PEX_TOOLS)")
class TestInitScriptOwnership(Temp):
    """Which copy of a script is the mod's own and which is a master's (the game's rules: a loose file beats every
    archive, a later archive beats an earlier one)."""

    def mod_plugin(self, path, masters=("Starfield.esm", "TestMaster.esm"), vmad=None):
        own = len(masters) << 24 | 0x800
        write(path, mk.plugin(0x1, list(masters), [mk.group("QUST", [
            mk.record("QUST", own, [mk.edid("SM_Quest"), vmad or mk.vmad([("SM:Main", [])])])])]))
        return path

    def test_mod_copy_of_a_master_script_is_the_mods_own(self):
        # The mod ships a changed TM:Api (Ping only), in its archive or loose. Its copy is the one the game runs:
        # Ping is the mod's own function, Hello (inherited from TM:Base) is still the master's, and the mod is
        # never listed as its own master.
        main = calls("SM:Main", "Quest", ("TM:Api", "Ping", ["int:1"]), ("TM:Api", "Hello", []))
        changed = mk.pex("TM:Api", "TM:Base", functions=[("Ping", [("aiValue", "Int")], [], [])])
        for how in ("archive", "loose"):
            with self.subTest(how):
                data, src = self.p(how, "Data"), self.p(how, "src")
                tm_world(data)
                files = [("scripts/SM/Main.pex", main)]
                if how == "archive":
                    files.append(("scripts/TM/Api.pex", changed))
                else:
                    write(os.path.join(src, "Scripts", "TM", "Api.pex"), changed)
                write(os.path.join(src, "ScriptMod - Main.ba2"), mk.ba2(files))
                mod = self.mod_plugin(os.path.join(src, "ScriptMod.esm"))
                mods, notes, summary = drift.init(mod, [data], TOOLS)
                self.assertEqual(list(mods["masters"]), ["TestMaster.esm"], notes)
                self.assertEqual(mods["masters"]["TestMaster.esm"]["functions"], {"scripts/TM/Base.pex": ["Hello"]})
                self.assertEqual(summary["scripts"], 2)
                self.assertFalse([n for n in notes if "defines now" in n or "argument" in n], notes)

    def test_function_from_the_mods_copy_of_a_parent(self):
        # The mod ships a changed TM:Base with a new function Extra(); its call TM:Api.Extra() (TM:Api is the
        # master's, its parent TM:Base the mod's) is the mod's own function, not "no master script defines it".
        data, src = self.p("Data"), self.p("src")
        tm_world(data)
        write(os.path.join(src, "ScriptMod - Main.ba2"), mk.ba2([
            ("scripts/SM/Main.pex", calls("SM:Main", "Quest", ("TM:Api", "Extra", []), ("TM:Api", "Pong", []))),
            ("scripts/TM/Base.pex", mk.pex("TM:Base", "ScriptObject", functions=[("Hello", [], [], []),
                                                                                ("Extra", [], [], [])]))]))
        mod = self.mod_plugin(os.path.join(src, "ScriptMod.esm"))
        mods, notes, summary = drift.init(mod, [data], TOOLS)
        self.assertEqual(list(mods["masters"]), ["TestMaster.esm"])
        self.assertEqual(mods["masters"]["TestMaster.esm"]["functions"], {"scripts/TM/Api.pex": ["Pong"]})
        self.assertFalse([n for n in notes if "defines now" in n], notes)

    def test_stage_above_65535_is_not_known(self):
        data, src = self.p("Data"), self.p("src")
        tm_world(data)
        write(os.path.join(src, "Scripts", "SM", "Main.pex"), mk.pex(
            "SM:Main", "Quest", variables=[("::Q_var", "Quest")], properties=[("Q", "Quest", "::Q_var")],
            functions=[("Go", [], [("::t1", "Bool")], [
                ("callmethod", ["ident:SetStage", "ident:::Q_var", "ident:::t1", "int:70000"]),
                ("callmethod", ["ident:SetStage", "ident:::Q_var", "ident:::t1", "int:-1"])])]))  # -1: no stage
        mod = self.mod_plugin(os.path.join(src, "ScriptMod.esm"), vmad=mk.vmad([("SM:Main", [("Q", 1, 0x01000800)])]))
        mods, notes, summary = drift.init(mod, [data], TOOLS)
        rec = mods["masters"]["TestMaster.esm"]["records"]
        self.assertEqual(len(rec), 1)
        self.assertNotIn("stages", rec[0])
        self.assertIn("isn't listed", rec[0]["why"])

    def test_safety_limit_is_a_note(self):
        data, src = self.p("Data"), self.p("src")
        tm_world(data)
        write(os.path.join(src, "ScriptMod - Main.ba2"), mk.ba2([
            ("scripts/SM/Main.pex", calls("SM:Main", "Quest", ("TM:Base", "Hello", []))),
            ("scripts/SM/Other.pex", calls("SM:Other", "Quest")), ("scripts/SM/Third.pex", calls("SM:Third", "Quest"))]))
        mod = self.mod_plugin(os.path.join(src, "ScriptMod.esm"))
        old, scripts.MAX_SCRIPTS = scripts.MAX_SCRIPTS, 1
        try:
            mods, notes, summary = drift.init(mod, [data], TOOLS)
        finally:
            scripts.MAX_SCRIPTS = old
        self.assertIn("stopped after 1 of your mod's own scripts; 2 more weren't read (a safety limit)", notes)
        self.assertEqual(summary["scripts"], 1)

    def test_loose_fragment_and_alias_scripts(self):
        # A loose install of a mod whose quest has a fragment script and an alias script: both are found through
        # the VMAD's fragment section, next to the plugin and in the shared Data folder alike. A constant stage
        # above 65535 isn't a stage number: the quest is marked "not known".
        qf = "Fragments:Quests:QF_SM_Quest_02000800"
        frag = mk.pex(qf, "Quest", variables=[("::TargetQuest_var", "Quest")],
                      properties=[("TargetQuest", "Quest", "::TargetQuest_var")],
                      functions=[("Fragment_Stage_0010", [], [("::t1", "Bool")], [
                          ("callmethod", ["ident:SetStage", "ident:::TargetQuest_var", "ident:::t1", "int:20"]),
                          ("callmethod", ["ident:SetStage", "ident:::TargetQuest_var", "ident:::t1", "int:70000"])])])
        alias = calls("SM:AliasScript", "ReferenceAlias", ("TM:Base", "Hello", []))
        tail = mk.quest_tail(qf, [("TargetQuest", 1, 0x01000800)], fragments=[(10, qf, "Fragment_Stage_0010")],
                             aliases=[(0, [("SM:AliasScript", [])])])
        for where in ("own folder", "Data folder"):
            with self.subTest(where):
                data = self.p(where, "Data")
                folder = data if where == "Data folder" else self.p(where, "src")
                tm_world(data)
                write(os.path.join(folder, "Scripts", "Fragments", "Quests", "QF_SM_Quest_02000800.pex"), frag)
                write(os.path.join(folder, "Scripts", "SM", "AliasScript.pex"), alias)
                # Another mod's loose scripts in the shared folder aren't read.
                write(os.path.join(data, "Scripts", "Fragments", "Quests", "QF_Other_00000800.pex"), b"not read")
                write(os.path.join(data, "Scripts", "Other", "Unrelated.pex"), b"not read")
                mod = self.mod_plugin(os.path.join(folder, "ScriptMod.esm"), vmad=mk.vmad([], tail=tail))
                mods, notes, summary = drift.init(mod, [data], TOOLS)
                tm = mods["masters"]["TestMaster.esm"]
                self.assertEqual(tm["functions"], {"scripts/TM/Base.pex": ["Hello"]})
                rec = tm["records"]
                self.assertEqual([(r["edid"], r["stages"]) for r in rec], [("TM_Quest", [20])])
                self.assertIn(f"Stages set by script {qf}", rec[0]["why"])
                self.assertIn("isn't listed", rec[0]["why"])
                self.assertEqual(summary["scripts"], 2)
                self.assertFalse([n for n in notes if "couldn't read" in n], notes)

    def test_shared_data_folder_namespaces(self):
        # The plugin is in the Data folder: Data\Scripts holds every mod's loose scripts. The mod's own are the ones
        # in its namespace (SM). FW:Api belongs to FrameworkMaster.esm (installed loose; its quest names FW:Quest),
        # so its call to TM:Api.Pong isn't the mod's. A loose copy of a master script is a note.
        data = self.p("Data")
        tm_world(data)
        write(os.path.join(data, "FrameworkMaster.esm"), mk.plugin(0x1, ["Starfield.esm"], [mk.group("QUST", [
            mk.record("QUST", 0x01000800, [mk.edid("FW_Quest"), mk.vmad([("FW:Quest", [])])])])]))
        scr = os.path.join(data, "Scripts")
        write(os.path.join(scr, "FW", "Quest.pex"), mk.pex("FW:Quest", "Quest"))
        write(os.path.join(scr, "FW", "Api.pex"), calls("FW:Api", "ScriptObject", ("TM:Api", "Pong", [])))
        write(os.path.join(scr, "SM", "Main.pex"), calls("SM:Main", "Quest", ("FW:Api", "DoIt", []),
                                                         ("SM:Helper", "Go", [])))
        write(os.path.join(scr, "SM", "Helper.pex"), calls("SM:Helper", "ScriptObject", ("TM:Base", "Hello", [])))
        write(os.path.join(scr, "TM", "Base.pex"), tm_base())
        mod = self.mod_plugin(os.path.join(data, "ScriptMod.esm"),
                              masters=("Starfield.esm", "TestMaster.esm", "FrameworkMaster.esm"))
        mods, notes, summary = drift.init(mod, [data], TOOLS)
        self.assertEqual(mods["masters"]["TestMaster.esm"]["functions"], {"scripts/TM/Base.pex": ["Hello"]})
        self.assertEqual(summary["scripts"], 2)
        self.assertTrue(any("holds loose copies of 1 master script(s) your scripts call (scripts/TM/Base.pex)" in n
                            for n in notes), notes)

    def test_shared_data_folder_bare_helper_reached_by_code(self):
        # The plugin is in the Data folder and names only ScriptModMain (no namespace). Its helper ScriptModHelper,
        # reached only through a callstatic, and its parent ScriptModBase are the mod's too (0.1.x read them), so
        # the helper's call to TM:Base.Hello is found. Another mod's bare loose script nothing of ours references
        # isn't read, and a loose bare copy of a master archive script the helper reaches stays the master's.
        data = self.p("Data")
        tm_world(data)
        write(os.path.join(data, "TestMaster - Extra.ba2"), mk.ba2([("scripts/MasterBare.pex", mk.pex("MasterBare",
                                                                                                  "ScriptObject"))]))
        scr = os.path.join(data, "Scripts")
        write(os.path.join(scr, "ScriptModMain.pex"), calls("ScriptModMain", "ScriptModBase",
                                                            ("ScriptModHelper", "Go", [])))
        write(os.path.join(scr, "ScriptModBase.pex"), calls("ScriptModBase", "Quest", ("TM:Api", "Pong", [])))
        write(os.path.join(scr, "ScriptModHelper.pex"), calls("ScriptModHelper", "ScriptObject",
                                                              ("TM:Base", "Hello", []),
                                                              variables=[("Other", "MasterBare")]))
        write(os.path.join(scr, "MasterBare.pex"), b"someone's loose copy: not read")
        write(os.path.join(scr, "OtherModScript.pex"), b"another mod's script: not read")
        mod = self.mod_plugin(os.path.join(data, "ScriptMod.esm"), vmad=mk.vmad([("ScriptModMain", [])]))
        mods, notes, summary = drift.init(mod, [data], TOOLS)
        self.assertEqual(mods["masters"]["TestMaster.esm"]["functions"],
                         {"scripts/TM/Api.pex": ["Pong"], "scripts/TM/Base.pex": ["Hello"]}, notes)
        self.assertEqual(summary["scripts"], 3)
        self.assertFalse([n for n in notes if "couldn't read" in n], notes)

    def test_shared_data_folder_bare_type_is_not_enough(self):
        # A bare loose script the mod's script only declares a variable of (another mod's object it holds) isn't
        # the mod's: its call to TM:Api.Pong isn't listed. The bare helpers it calls with callstatic are, and a note
        # lists them (20 names, then "and N more").
        data = self.p("Data")
        tm_world(data)
        scr = os.path.join(data, "Scripts")
        helpers = [f"ScriptModHelper{i:02d}" for i in range(22)]
        write(os.path.join(scr, "ScriptModMain.pex"), calls("ScriptModMain", "Quest", ("TM:Base", "Hello", []),
                                                            *[(h, "Go", []) for h in helpers],
                                                            variables=[("Held", "OtherModThing")]))
        for h in helpers:
            write(os.path.join(scr, h + ".pex"), calls(h, "ScriptObject"))
        write(os.path.join(scr, "OtherModThing.pex"), calls("OtherModThing", "ScriptObject", ("TM:Api", "Pong", [])))
        mod = self.mod_plugin(os.path.join(data, "ScriptMod.esm"), vmad=mk.vmad([("ScriptModMain", [])]))
        mods, notes, summary = drift.init(mod, [data], TOOLS)
        self.assertEqual(mods["masters"]["TestMaster.esm"]["functions"], {"scripts/TM/Base.pex": ["Hello"]}, notes)
        self.assertEqual(summary["scripts"], 23)
        self.assertIn(f"22 loose script(s) in {scr} with no namespace (or Fragments:) were read as your mod's own "
                      f"because your scripts extend them or call them with callstatic: {', '.join(helpers[:20])} "
                      f"and 2 more", notes)

    def test_failed_script_part_says_so(self):
        data, src = self.p("Data"), self.p("src")
        tm_world(data)
        mod = os.path.join(src, "ScriptMod.esm")
        write(mod, mk.plugin(0x1, ["Starfield.esm", "TestMaster.esm"], [
            mk.group("QUST", [mk.record("QUST", 0x01000800, [mk.edid("TM_Quest")])])]))

        def broken(*_a):
            raise scripts.ScriptError("made-up failure")
        old, scripts.analyze = scripts.analyze, broken
        try:
            code, out = run("drift", "init", mod, "-o", self.p("m.json"), "--data", data, "--pex-tools", TOOLS.folder)
        finally:
            scripts.analyze = old
        self.assertEqual(code, 0, out)
        self.assertIn(": 1 overridden record(s) in 1 master(s)\n", out)
        self.assertNotIn("read None", out)
        self.assertNotIn("function(s) your scripts call", out)
        self.assertIn("note: scripts not read: made-up failure", out)
        self.assertIn("Next: add the quest stages your scripts set and the master script functions they call by "
                      "hand", out)
        with open(self.p("m.json"), encoding="utf-8") as f:
            self.assertIn("its scripts couldn't be read", json.load(f)["about"])


if __name__ == "__main__":
    unittest.main(verbosity=1)
