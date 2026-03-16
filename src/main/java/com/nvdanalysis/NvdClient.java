package com.nvdanalysis;

import com.google.gson.*;
import okhttp3.*;

import java.io.IOException;
import java.util.*;
import java.util.concurrent.TimeUnit;

public class NvdClient {

    private static final String[][] PERIODS = {
        {"2010-01-01T00:00:00.000","2010-04-11T00:00:00.000"},
        {"2010-04-11T00:00:00.000","2010-07-20T00:00:00.000"},
        {"2010-07-20T00:00:00.000","2010-10-28T00:00:00.000"},
        {"2010-10-28T00:00:00.000","2011-02-05T00:00:00.000"},
        {"2011-02-05T00:00:00.000","2011-05-16T00:00:00.000"},
        {"2011-05-16T00:00:00.000","2011-08-24T00:00:00.000"},
        {"2011-08-24T00:00:00.000","2011-12-02T00:00:00.000"},
        {"2011-12-02T00:00:00.000","2012-03-11T00:00:00.000"},
        {"2012-03-11T00:00:00.000","2012-06-19T00:00:00.000"},
        {"2012-06-19T00:00:00.000","2012-09-27T00:00:00.000"},
        {"2012-09-27T00:00:00.000","2013-01-05T00:00:00.000"},
        {"2013-01-05T00:00:00.000","2013-04-15T00:00:00.000"},
        {"2013-04-15T00:00:00.000","2013-07-24T00:00:00.000"},
        {"2013-07-24T00:00:00.000","2013-11-01T00:00:00.000"},
        {"2013-11-01T00:00:00.000","2014-02-09T00:00:00.000"},
        {"2014-02-09T00:00:00.000","2014-05-20T00:00:00.000"},
        {"2014-05-20T00:00:00.000","2014-08-28T00:00:00.000"},
        {"2014-08-28T00:00:00.000","2014-12-06T00:00:00.000"},
        {"2014-12-06T00:00:00.000","2015-03-16T00:00:00.000"},
        {"2015-03-16T00:00:00.000","2015-06-24T00:00:00.000"},
        {"2015-06-24T00:00:00.000","2015-10-02T00:00:00.000"},
        {"2015-10-02T00:00:00.000","2016-01-10T00:00:00.000"},
        {"2016-01-10T00:00:00.000","2016-04-19T00:00:00.000"},
        {"2016-04-19T00:00:00.000","2016-07-28T00:00:00.000"},
        {"2016-07-28T00:00:00.000","2016-11-05T00:00:00.000"},
        {"2016-11-05T00:00:00.000","2017-02-13T00:00:00.000"},
        {"2017-02-13T00:00:00.000","2017-05-24T00:00:00.000"},
        {"2017-05-24T00:00:00.000","2017-09-01T00:00:00.000"},
        {"2017-09-01T00:00:00.000","2017-12-10T00:00:00.000"},
        {"2017-12-10T00:00:00.000","2018-03-20T00:00:00.000"},
        {"2018-03-20T00:00:00.000","2018-06-28T00:00:00.000"},
        {"2018-06-28T00:00:00.000","2018-10-06T00:00:00.000"},
        {"2018-10-06T00:00:00.000","2019-01-14T00:00:00.000"},
        {"2019-01-14T00:00:00.000","2019-04-24T00:00:00.000"},
        {"2019-04-24T00:00:00.000","2019-08-02T00:00:00.000"},
        {"2019-08-02T00:00:00.000","2019-11-10T00:00:00.000"},
        {"2019-11-10T00:00:00.000","2020-02-18T00:00:00.000"},
        {"2020-02-18T00:00:00.000","2020-05-28T00:00:00.000"},
        {"2020-05-28T00:00:00.000","2020-09-05T00:00:00.000"},
        {"2020-09-05T00:00:00.000","2020-12-14T00:00:00.000"},
        {"2020-12-14T00:00:00.000","2021-03-24T00:00:00.000"},
        {"2021-03-24T00:00:00.000","2021-07-02T00:00:00.000"},
        {"2021-07-02T00:00:00.000","2021-10-10T00:00:00.000"},
        {"2021-10-10T00:00:00.000","2021-12-31T23:59:59.999"},
    };

    private final OkHttpClient http;
    private final String apiKey;
    private final Gson gson = new Gson();

    public NvdClient(String apiKey) {
        this.apiKey = apiKey;
        this.http   = new OkHttpClient.Builder()
                .connectTimeout(30, TimeUnit.SECONDS)
                .readTimeout(30, TimeUnit.SECONDS)
                .build();
    }

    public List<CveRecord> fetchAll(String keyword) {
        List<CveRecord> results = new ArrayList<>();
        Set<String> seen = new HashSet<>();

        for (String[] period : PERIODS) {
            int startIndex = 0;
            while (true) {
                String url = "https://services.nvd.nist.gov/rest/json/cves/2.0?"
                        + "keywordSearch=" + keyword.replace(" ", "%20")
                        + "&pubStartDate=" + period[0]
                        + "&pubEndDate="   + period[1]
                        + "&resultsPerPage=2000"
                        + "&startIndex="   + startIndex;

                Request.Builder req = new Request.Builder()
                        .url(url)
                        .header("User-Agent", "Mozilla/5.0");
                if (apiKey != null && !apiKey.isEmpty())
                    req.header("apiKey", apiKey);

                try (Response response = http.newCall(req.build()).execute()) {
                    if (!response.isSuccessful()) {
                        System.out.println("    HTTP " + response.code() + " [" + period[0].substring(0, 7) + "]");
                        break;
                    }
                    JsonObject body = gson.fromJson(response.body().string(), JsonObject.class);
                    int total       = body.get("totalResults").getAsInt();
                    JsonArray vulns = body.getAsJsonArray("vulnerabilities");

                    for (JsonElement v : vulns) {
                        CveRecord rec = parseCve(v.getAsJsonObject());
                        if (rec != null && !seen.contains(rec.cveId)) {
                            seen.add(rec.cveId);
                            results.add(rec);
                        }
                    }

                    if (startIndex + 2000 >= total) break;
                    startIndex += 2000;
                    sleep(apiKey != null && !apiKey.isEmpty() ? 700 : 6500);

                } catch (IOException e) {
                    System.out.println("    ERROR: " + e.getMessage());
                    break;
                }
            }
            sleep(apiKey != null && !apiKey.isEmpty() ? 700 : 6500);
        }

        System.out.println("    '" + keyword + "': " + results.size() + " total");
        return results;
    }

    private CveRecord parseCve(JsonObject entry) {
        JsonObject cve = entry.getAsJsonObject("cve");
        if (cve == null) return null;

        CveRecord rec    = new CveRecord();
        rec.cveId        = getString(cve, "id");
        rec.status       = getString(cve, "vulnStatus");
        String published = getString(cve, "published");
        rec.year         = published.length() >= 4 ? published.substring(0, 4) : "unknown";
        rec.description  = "";

        JsonArray descs = cve.getAsJsonArray("descriptions");
        if (descs != null) {
            for (JsonElement d : descs) {
                JsonObject o = d.getAsJsonObject();
                if ("en".equals(getString(o, "lang"))) {
                    rec.description = getString(o, "value");
                    break;
                }
            }
        }

        rec.cwe = "N/A";
        JsonArray weaknesses = cve.getAsJsonArray("weaknesses");
        if (weaknesses != null && weaknesses.size() > 0) {
            JsonArray wd = weaknesses.get(0).getAsJsonObject().getAsJsonArray("description");
            if (wd != null && wd.size() > 0)
                rec.cwe = getString(wd.get(0).getAsJsonObject(), "value");
        }

        JsonObject metrics = cve.getAsJsonObject("metrics");
        if (metrics != null) {
            JsonArray v31 = metrics.getAsJsonArray("cvssMetricV31");
            JsonArray v30 = metrics.getAsJsonArray("cvssMetricV30");
            JsonArray v2  = metrics.getAsJsonArray("cvssMetricV2");

            if (v31 != null && v31.size() > 0) {
                JsonObject d   = v31.get(0).getAsJsonObject().getAsJsonObject("cvssData");
                rec.cvssV3     = getDouble(d, "baseScore");
                rec.cvssV3Severity = getString(d, "baseSeverity");
                rec.cvssSource = "v3.1";
            } else if (v30 != null && v30.size() > 0) {
                JsonObject d   = v30.get(0).getAsJsonObject().getAsJsonObject("cvssData");
                rec.cvssV3     = getDouble(d, "baseScore");
                rec.cvssV3Severity = getString(d, "baseSeverity");
                rec.cvssSource = "v3.0";
            }

            if (v2 != null && v2.size() > 0) {
                JsonObject d = v2.get(0).getAsJsonObject().getAsJsonObject("cvssData");
                rec.cvssV2   = getDouble(d, "baseScore");
                if (rec.cvssSource == null) rec.cvssSource = "v2_only";
            }
        }

        return rec;
    }

    private String getString(JsonObject obj, String key) {
        JsonElement el = obj.get(key);
        return (el != null && !el.isJsonNull()) ? el.getAsString() : "";
    }

    private Double getDouble(JsonObject obj, String key) {
        JsonElement el = obj.get(key);
        return (el != null && !el.isJsonNull()) ? el.getAsDouble() : null;
    }

    private void sleep(long ms) {
        try { Thread.sleep(ms); } catch (InterruptedException ignored) {}
    }
}
