package com.nvdanalysis;

import java.util.*;
import java.util.stream.Collectors;

public class Analyzer {

    private static final int COVERAGE_THRESHOLD = 10;

    public List<CveRecord> clean(List<CveRecord> records) {
        Map<String, Integer> excluded = new LinkedHashMap<>();
        excluded.put("REJECTED",       0);
        excluded.put("DISPUTED",       0);
        excluded.put("no_description", 0);
        excluded.put("no_cvss",        0);

        List<CveRecord> clean = new ArrayList<>();
        for (CveRecord r : records) {
            String s = r.status.toUpperCase();
            if (s.contains("REJECTED"))  { excluded.merge("REJECTED",       1, Integer::sum); continue; }
            if (s.contains("DISPUTED"))  { excluded.merge("DISPUTED",       1, Integer::sum); continue; }
            if (r.description == null || r.description.trim().isEmpty()) { excluded.merge("no_description", 1, Integer::sum); continue; }
            if (r.cvssV3 == null && r.cvssV2 == null) { excluded.merge("no_cvss", 1, Integer::sum); continue; }
            clean.add(r);
        }

        System.out.println("\n  Excluded: " + excluded);
        System.out.println("  D_clean:  " + clean.size() + " records");
        return clean;
    }

    public void analyze(List<CveRecord> records, Threat threat) {
        int n = records.size();
        System.out.println("\n" + repeat("=", 56));
        System.out.printf("  %s - %s  [%s]%n", threat.pid, threat.name, threat.serviceModel);
        System.out.println(repeat("=", 56));
        System.out.println("  Total CVEs: " + n);

        if (n == 0) {
            System.out.println("  *** GAP - no signal in NVD ***");
            return;
        }

        System.out.println("  RQ1: " + (n >= COVERAGE_THRESHOLD ? "COVERED" : "GAP (N < 10)"));

        List<Double> v3 = records.stream().filter(r -> r.cvssV3 != null).map(r -> r.cvssV3).collect(Collectors.toList());
        List<Double> v2 = records.stream().filter(r -> r.cvssV2 != null).map(r -> r.cvssV2).collect(Collectors.toList());

        System.out.println("\n  -- CVSS v3 (" + v3.size() + " records) --");
        if (!v3.isEmpty()) {
            double min = v3.stream().mapToDouble(d -> d).min().orElse(0);
            double max = v3.stream().mapToDouble(d -> d).max().orElse(0);
            System.out.printf("     Median:           %.1f%n", median(v3));
            System.out.printf("     Min / Max:        %.1f / %.1f%n", min, max);
            System.out.printf("     Critical (>=9.0): %d  (%.1f%%)%n", count(v3, 9.0, 10.1), pct(count(v3, 9.0, 10.1), v3.size()));
            System.out.printf("     High (7.0-8.9):   %d  (%.1f%%)%n", count(v3, 7.0, 9.0),  pct(count(v3, 7.0, 9.0),  v3.size()));
            System.out.printf("     Medium (4.0-6.9): %d  (%.1f%%)%n", count(v3, 4.0, 7.0),  pct(count(v3, 4.0, 7.0),  v3.size()));
            System.out.printf("     Low (<4.0):       %d  (%.1f%%)%n", count(v3, 0.0, 4.0),  pct(count(v3, 0.0, 4.0),  v3.size()));
        }

        System.out.println("\n  -- CVSS v2 (" + v2.size() + " records) --");
        if (!v2.isEmpty()) {
            System.out.printf("     Median:    %.1f%n", median(v2));
            System.out.printf("     Min / Max: %.1f / %.1f%n",
                    v2.stream().mapToDouble(d -> d).min().orElse(0),
                    v2.stream().mapToDouble(d -> d).max().orElse(0));
        }

        System.out.println("\n  -- CVE trend by year --");
        Map<String, Long> yearCounts = records.stream()
                .collect(Collectors.groupingBy(r -> r.year, Collectors.counting()));
        for (int y = 2010; y <= 2021; y++) {
            long c   = yearCounts.getOrDefault(String.valueOf(y), 0L);
            String bar = repeat("#", (int) Math.min(c, 40));
            System.out.printf("     %d: %-40s %d%n", y, bar, c);
        }

        System.out.println("\n  -- Top 10 CWE --");
        records.stream()
                .collect(Collectors.groupingBy(r -> r.cwe, Collectors.counting()))
                .entrySet().stream()
                .sorted(Map.Entry.<String, Long>comparingByValue().reversed())
                .limit(10)
                .forEach(e -> System.out.printf("     %-30s %d%n", e.getKey(), e.getValue()));
    }

    private double median(List<Double> values) {
        List<Double> s = new ArrayList<>(values);
        Collections.sort(s);
        int mid = s.size() / 2;
        return s.size() % 2 == 0 ? (s.get(mid - 1) + s.get(mid)) / 2.0 : s.get(mid);
    }

    private long count(List<Double> values, double from, double to) {
        return values.stream().filter(d -> d >= from && d < to).count();
    }

    private double pct(long count, int total) {
        return total == 0 ? 0 : count * 100.0 / total;
    }

    private String repeat(String s, int n) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < n; i++) sb.append(s);
        return sb.toString();
    }
}
