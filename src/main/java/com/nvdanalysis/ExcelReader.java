package com.nvdanalysis;

import org.apache.poi.ss.usermodel.*;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;

import java.io.FileInputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class ExcelReader {

    public static List<Threat> read(String path) throws Exception {
        List<Threat> threats = new ArrayList<>();

        try (FileInputStream fis = new FileInputStream(path);
             Workbook wb = new XSSFWorkbook(fis)) {

            Sheet sheet = wb.getSheet("T_CORPUS_INPUT");
            if (sheet == null) sheet = wb.getSheetAt(0);

            for (int i = 2; i <= sheet.getLastRowNum(); i++) {
                Row row = sheet.getRow(i);
                if (row == null) continue;

                String pid          = cell(row, 0);
                String name         = cell(row, 1);
                String serviceModel = cell(row, 3);
                String keywordsRaw  = cell(row, 4);

                if (pid.isEmpty() || name.isEmpty()) continue;

                List<String> keywords = new ArrayList<>();
                for (String kw : keywordsRaw.split(",")) {
                    String trimmed = kw.trim();
                    if (!trimmed.isEmpty()) keywords.add(trimmed);
                }

                if (keywords.isEmpty()) keywords.add(name);

                threats.add(new Threat(pid, name, serviceModel, keywords));
            }
        }

        return threats;
    }

    private static String cell(Row row, int col) {
        Cell c = row.getCell(col);
        if (c == null) return "";
        switch (c.getCellType()) {
            case STRING:  return c.getStringCellValue().trim();
            case NUMERIC: return String.valueOf((int) c.getNumericCellValue());
            default:      return "";
        }
    }
}
