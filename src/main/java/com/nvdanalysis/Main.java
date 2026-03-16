package com.nvdanalysis;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.Collectors;

public class Main {

    static final String API_KEY    = "46ac08cd-9119-4dbc-bd7f-40c5ff32e71e";
    static final String EXCEL_PATH = "T_corpus.xlsx";

    public static void main(String[] args) throws Exception {
        System.out.println("NVD Analysis - " + LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm")));
        System.out.println("API key: " + (API_KEY.isEmpty() ? "NO (rate limit: 5 req/30s)" : "YES"));

        List<Threat> corpus = ExcelReader.read(EXCEL_PATH);
        System.out.println("Threats loaded from Excel: " + corpus.size());
        System.out.println();

        NvdClient   client      = new NvdClient(API_KEY);
        Analyzer    analyzer    = new Analyzer();
        CsvExporter exporter    = new CsvExporter();

        Map<String, CveRecord>   allRecords  = new LinkedHashMap<>();
        Map<String, Set<String>> assignments = new LinkedHashMap<>();

        for (Threat threat : corpus) {
            System.out.println("\n[" + threat.pid + "] " + threat.name);
            Set<String> pidIds = new LinkedHashSet<>();

            for (String keyword : threat.keywords) {
                List<CveRecord> results = client.fetchAll(keyword);
                for (CveRecord rec : results) {
                    if (rec.cveId != null && !rec.cveId.isEmpty()) {
                        allRecords.put(rec.cveId, rec);
                        pidIds.add(rec.cveId);
                    }
                }
                Thread.sleep(1000);
            }

            for (String cveId : pidIds)
                assignments.computeIfAbsent(cveId, k -> new LinkedHashSet<>()).add(threat.pid);

            System.out.println("  Unique CVEs for " + threat.pid + ": " + pidIds.size());
        }

        System.out.println("\nCLEANING - raw records: " + allRecords.size());
        List<CveRecord> clean = analyzer.clean(new ArrayList<>(allRecords.values()));

        exporter.export(clean, assignments, "D_clean.csv");

        System.out.println("\nANALYSIS BY CATEGORY");
        for (Threat threat : corpus) {
            String pid = threat.pid;
            List<CveRecord> catRecords = clean.stream()
                    .filter(r -> assignments.getOrDefault(r.cveId, Collections.emptySet()).contains(pid))
                    .collect(Collectors.toList());
            analyzer.analyze(catRecords, threat);
        }

        long overlaps = clean.stream()
                .filter(r -> assignments.getOrDefault(r.cveId, Collections.emptySet()).size() > 1)
                .count();
        if (overlaps > 0)
            System.out.println("\n  OVERLAP: " + overlaps + " CVEs assigned to multiple categories");

        System.out.println("\n" + repeat("=", 56));
        System.out.println("  DONE - D_clean.csv: " + clean.size() + " records");
        System.out.println(repeat("=", 56));
    }

    private static String repeat(String s, int n) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < n; i++) sb.append(s);
        return sb.toString();
    }
}
