import sys
import tempfile
import unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from analyze import read_nmap, read_traffic, report

class AnalyzerTests(unittest.TestCase):
    def test_hosts(self):
        self.assertEqual(len(read_nmap(ROOT / "samples/nmap_demo.xml")), 2)
    def test_ports(self):
        self.assertEqual(len(read_nmap(ROOT / "samples/nmap_demo.xml")[0]["ports"]), 2)
    def test_open(self):
        self.assertEqual(read_nmap(ROOT / "samples/nmap_demo.xml")[0]["ports"][0]["state"], "open")
    def test_packets(self):
        self.assertEqual(read_traffic(ROOT / "samples/traffic_demo.csv")["packets"], 5)
    def test_dns(self):
        self.assertEqual(read_traffic(ROOT / "samples/traffic_demo.csv")["protocols"]["DNS"], 2)
    def test_conversations(self):
        self.assertEqual(sum(read_traffic(ROOT / "samples/traffic_demo.csv")["conversations"].values()), 5)
    def test_disclaimer(self):
        self.assertIn("SYNTHETIC", report([], {"packets": 0, "protocols": {}, "conversations": {}}, True))
    def test_invalid_csv(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "bad.csv"
            path.write_text("foo,bar\na,b\n")
            with self.assertRaises(ValueError):
                read_traffic(path)

    def test_empty_traffic_csv(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "empty.csv"
            path.write_text("Source,Destination,Protocol\n")
            self.assertEqual(read_traffic(path)["packets"], 0)

    def test_invalid_nmap_root(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "invalid.xml"
            path.write_text("<notnmap/>")
            with self.assertRaises(ValueError):
                read_nmap(path)

    def test_no_ports(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "empty_ports.xml"
            path.write_text('<nmaprun><host><address addr="192.0.2.30"/></host></nmaprun>')
            self.assertEqual(read_nmap(path)[0]["ports"], [])

    def test_report_contains_protocols(self):
        traffic = read_traffic(ROOT / "samples/traffic_demo.csv")
        text = report([], traffic, True)
        self.assertIn("- DNS: 2", text)
