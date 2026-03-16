package com.nvdanalysis;

import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.*;

public class CsvExporter {

    public void export(List<CveRecord> records, Map<String, Set<String>> assignments, String filename) throws IOException {
        try (PrintWriter pw = new PrintWriter(new FileWriter(filename))) {
            pw.println("cve_id,year,cwe,cvss_v3,cvss_v3_severity,cvss_v2,cvss_source,threat_ids,overlap_flag");
            for (CveRecord r : records) {
                Set<String> cats = assignments.getOrDefault(r.cveId, new HashSet<>());
                pw.printf("%s,%s,%s,%s,%s,%s,%s,%s,%b%n",
                        r.cveId,
                        r.year,
                        r.cwe,
                        r.cvssV3 != null ? r.cvssV3 : "",
                        r.cvssV3Severity != null ? r.cvssV3Severity : "",
                        r.cvssV2 != null ? r.cvssV2 : "",
                        r.cvssSource != null ? r.cvssSource : "",
                        String.join("|", cats),
                        cats.size() > 1);
            }
        }
        System.out.println("  D_clean.csv saved");
    }
}
