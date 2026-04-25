import importlib.util
import sys
import types
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load_builder():
    ebooklib = types.ModuleType("ebooklib")
    epub = types.SimpleNamespace(
        EpubBook=object,
        EpubItem=object,
        EpubHtml=object,
        EpubNcx=lambda: object(),
        EpubNav=lambda: object(),
        Section=lambda title: title,
        write_epub=lambda *args, **kwargs: None,
    )
    ebooklib.epub = epub
    sys.modules.setdefault("ebooklib", ebooklib)
    sys.modules.setdefault("ebooklib.epub", epub)
    spec = importlib.util.spec_from_file_location("builder", ROOT / "build_rfc_collection.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["builder"] = module
    spec.loader.exec_module(module)
    return module


class HeaderReferenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.builder = load_builder()

    def test_tcp_header_reference_renders_bit_layout_and_hunting_descriptions(self):
        panel = self.builder.render_header_reference_panel(793)

        self.assertIn('class="header-reference-panel"', panel)
        self.assertIn('open', panel, "desktop panel should be open by default")
        self.assertIn('RFC 793 TCP Header', panel)
        self.assertIn('0-31', panel)
        self.assertIn('Source Port', panel)
        self.assertIn('Sequence Number', panel)
        self.assertIn('TCP Flags', panel)
        self.assertIn('SYN/ACK/RST/FIN combinations', panel)
        self.assertIn('width="160"', panel, "16-bit fields should span half of a 32-bit row")
        self.assertIn('width="320"', panel, "32-bit fields should span a full 32-bit row")

    def test_bgp_header_reference_renders_message_header_and_path_attributes(self):
        panel = self.builder.render_header_reference_panel(4271)

        self.assertIn('RFC 4271 BGP Message Header', panel)
        self.assertIn('Marker', panel)
        self.assertIn('Length', panel)
        self.assertIn('Type', panel)
        self.assertIn('Path Attributes', panel)
        self.assertIn('AS_PATH manipulation is the primary vector for route hijacking', panel)
        self.assertIn('width="320"', panel, "32-bit rows should be represented in the visual layout")

    def test_unknown_rfc_has_no_header_reference_panel(self):
        self.assertEqual("", self.builder.render_header_reference_panel(9999))


if __name__ == "__main__":
    unittest.main()
