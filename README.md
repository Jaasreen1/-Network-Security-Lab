# Network Security Lab

A reproducible Python lab for analyzing **Nmap XML exports** and **Wireshark CSV packet exports**.

> **Project status:** Functional analyzer with **synthetic demonstration data**. No real scans or packet captures have been performed for this repository. Demo results are not security findings.

## Features
- Parse Nmap XML to summarize hosts, ports, states, and reported services.
- Parse Wireshark CSV to summarize packet counts, protocols, and source/destination conversations.
- Generate a Markdown report.
- Unit tests and GitHub Actions workflow.
- No external Python dependencies and no active scanning.

## Run locally

Requires Python 3.10+.

```bash
python -m unittest discover -s tests -v
python src/analyze.py --nmap samples/nmap_demo.xml --traffic samples/traffic_demo.csv --output reports/informe_demo.md
```

The generated report is saved to `reports/informe_demo.md`.

## Project layout

- `src/analyze.py`: Python analyzer
- `samples/`: clearly labeled **synthetic** sample exports
- `tests/`: automated unit tests
- `docs/METODOLOGIA.md`: methodology, ethics, and limitations
- `.github/workflows/tests.yml`: CI test workflow

## Using authorized real exports

1. Obtain Nmap XML and Wireshark CSV only from systems and networks you own or are explicitly authorized to assess.
2. For the CSV, include columns named `Source`, `Destination`, and `Protocol`.
3. Review and sanitize sensitive data before uploading any reports.
4. Run the command above with your own file paths.

**Interpretation warning:** An open port is not proof of a vulnerability, and packet counts are not proof of an intrusion. This tool reports metadata only; independent validation is required.
