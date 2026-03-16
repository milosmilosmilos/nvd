# NVD Cloud Security Taxonomy Validator

Empirical validation of cloud security threat taxonomies against NVD vulnerability data.
Based on: Khoda Parast et al. (2021) — *Cloud computing security: A survey of service-based models*

## What it does

Queries the NVD REST API for each threat category defined in T_corpus,
collects CVE records for the period 2010–2021, cleans the dataset,
and produces per-category analysis: coverage (RQ1), CVSS severity (RQ2),
temporal trend (RQ3), and CWE distribution (RQ4).

## Requirements
```bash
# Java
Java 11+
Maven 3.6+

# Dependencies (auto-resolved via Maven)
OkHttp 4.12.0
Gson 2.10.1
Apache POI 5.2.3
```

Register for a free NVD API key at:
`https://nvd.nist.gov/developers/request-an-api-key`

Open `Main.java` and set:
```java
static final String API_KEY    = "your-key-here";
static final String EXCEL_PATH = "T_corpus_input_example.xlsx";
```

## Input

Place `T_corpus_input_example.xlsx` in the project root.
The Excel file defines the threat corpus — one row per threat category with:
- **Column A** — P-ID (e.g. P-01)
- **Column B** — Threat name
- **Column D** — Service model (IaaS / PaaS / SaaS / Generic)
- **Column E** — Keywords, comma-separated


## Output

| File | Description |
|------|-------------|
| `D_clean.csv` | Cleaned CVE dataset — one row per CVE |
| Console output | Per-category analysis: N CVEs, CVSS distribution, yearly trend, top CWEs |

## D_clean.csv schema

| Field | Description |
|-------|-------------|
| `cve_id` | CVE identifier |
| `year` | Publication year |
| `cwe` | Primary CWE identifier |
| `cvss_v3` | CVSS v3 base score |
| `cvss_v3_severity` | LOW / MEDIUM / HIGH / CRITICAL |
| `cvss_v2` | CVSS v2 base score |
| `cvss_source` | v3.1 / v3.0 / v2_only |
| `threat_ids` | Assigned category P-IDs (pipe-separated) |
| `overlap_flag` | TRUE if assigned to more than one category |

## Project structure
```
nvd-java/
├── pom.xml
└── src/main/java/com/nvdanalysis/
    ├── Main.java          — entry point, T_corpus definition
    ├── NvdClient.java     — NVD API queries (44 × 100-day periods)
    ├── Analyzer.java      — cleaning and per-category analysis
    ├── CsvExporter.java   — D_clean.csv export
    ├── ExcelReader.java   — reads T_corpus from Excel
    ├── CveRecord.java     — CVE data model
    └── Threat.java        — threat category model
```

## Notes

- Without an API key: rate limit is 5 requests / 30 seconds (slow)
- With an API key: rate limit is 50 requests / 30 seconds
- Full run over all 25 categories takes approximately 2–4 hours without a key, 15–30 minutes with a key
- The NVD API enforces a 120-day maximum date range per query — the code handles this automatically via 44 consecutive 100-day intervals

## Reference

F. Khoda Parast, C. Sindhav, S. Nikam, H. Izadi Yekta, K. B. Kent, S. Hakak,
*Cloud computing security: A survey of service-based models*,
Computers & Security, vol. 114, 2022.
DOI: [10.1016/j.cose.2021.102580](https://doi.org/10.1016/j.cose.2021.102580)
```
