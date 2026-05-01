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

        self.assertIn('RFC 4271 BGP Update Attributes', panel)
        self.assertIn('Attr Flags', panel)
        self.assertIn('Attr Type', panel)
        self.assertIn('ORIGIN', panel)
        self.assertIn('AS_PATH', panel)
        self.assertIn('Primary vector for hijacking', panel)
        self.assertIn('0-31 bit layout diagram', panel)

    def test_arp_ethernet_frame_reference_renders_key_resolution_fields(self):
        panel = self.builder.render_header_reference_panel(826)

        self.assertIn('RFC 826 ARP over Ethernet Frame', panel)
        self.assertIn('Hardware Type', panel)
        self.assertIn('Protocol Type', panel)
        self.assertIn('Sender MAC', panel)
        self.assertIn('Target IP', panel)
        self.assertIn('critical poisoning signals', panel)
        self.assertIn('width="160"', panel, "16-bit fields should span half of a 32-bit row")
        self.assertIn('width="320"', panel, "32-bit rows should be represented in the visual layout")

    def test_arp_inline_reference_injects_next_to_packet_format(self):
        body = "<pre>intro\nPacket format:\n--------------\nugly field prose\n</pre>"

        updated, inserted = self.builder.inject_inline_header_reference(826, body)

        self.assertTrue(inserted)
        self.assertIn('class="header-reference-panel inline-header-reference"', updated)
        self.assertIn('RFC 826 ARP over Ethernet Frame', updated)
        self.assertLess(updated.index('Packet format:'), updated.index('inline-header-reference'))
        self.assertLess(updated.index('inline-header-reference'), updated.index('ugly field prose'))

    def test_arp_receive_flow_chart_renders_rfc_decision_path(self):
        chart = self.builder.render_arp_receive_flow_chart()

        self.assertIn('class="arp-flowchart-panel"', chart)
        self.assertIn('RFC 826 ARP Packet Reception Flow', chart)
        self.assertIn('Do I have the hardware type in ar$hrd?', chart)
        self.assertIn('Do I speak the protocol in ar$pro?', chart)
        self.assertIn('Merge_flag := false', chart)
        self.assertIn('NOW look at ar$op', chart)
        self.assertIn('Set ar$op = ares_op$REPLY', chart)
        self.assertIn('Send reply on the same hardware', chart)
        self.assertIn('Discard / stop', chart)

    def test_arp_receive_flow_chart_injects_next_to_packet_reception(self):
        body = "<pre>before\nPacket Reception:\n-----------------\n\noriginal flow prose\n</pre>"

        updated, inserted = self.builder.inject_arp_receive_flow_chart(826, body)

        self.assertTrue(inserted)
        self.assertIn('class="arp-flowchart-panel"', updated)
        self.assertLess(updated.index('Packet Reception:'), updated.index('arp-flowchart-panel'))
        self.assertLess(updated.index('arp-flowchart-panel'), updated.index('original flow prose'))

    def test_study_plan_renders_tracks_and_research_links(self):
        section = self.builder.render_study_plan()

        self.assertIn('Study like a hunter, not a hostage.', section)
        self.assertIn('data-path="foundation"', section)
        self.assertIn('RFC 768', section)
        self.assertIn('Save pact', section)
        self.assertIn('10.1037/0033-2909.132.3.354', section)
        self.assertIn('10.1016/S0065-2601(06)38002-1', section)

    def test_unknown_rfc_has_no_header_reference_panel(self):
        self.assertEqual("", self.builder.render_header_reference_panel(9999))


if __name__ == "__main__":
    unittest.main()
