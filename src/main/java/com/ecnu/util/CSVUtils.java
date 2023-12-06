package com.ecnu.util;

import com.alibaba.fastjson.JSONObject;
import com.opencsv.CSVWriter;
import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.ss.usermodel.Sheet;
import org.apache.poi.ss.usermodel.Workbook;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;

import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.util.List;
import java.util.Map;

public class CSVUtils {

    public static void writeJSONToCSV(List<JSONObject> jsonData, String filePath) {
        try (CSVWriter writer = new CSVWriter(new FileWriter(filePath))) {
            // 写入CSV的标题行
            Map<String, Object> head = jsonData.get(0);
            String[] header = head.keySet().toArray(new String[0]);
            writer.writeNext(header);

            // 写入CSV的数据行
            for (Map<String, Object> row : jsonData) {
                String[] line = new String[header.length];
                int i = 0;
                for (String key : header) {
                    line[i++] = row.getOrDefault(key, "").toString();
                }
                writer.writeNext(line);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void writeJSONToXLSX(List<JSONObject> jsonData, String filePath) {
        try (Workbook workbook = new XSSFWorkbook()) {
            Sheet sheet = workbook.createSheet("Sheet1");

            // 写入标题行
            Map<String, Object> head = jsonData.get(0);
            Row headerRow = sheet.createRow(0);
            int headerIndex = 0;
            for (String key : head.keySet()) {
                Cell cell = headerRow.createCell(headerIndex++);
                cell.setCellValue(key);
            }

            // 写入数据行
            int rowIndex = 1;
            for (Map<String, Object> row : jsonData) {
                Row dataRow = sheet.createRow(rowIndex++);
                int cellIndex = 0;
                for (String key : head.keySet()) {
                    Cell cell = dataRow.createCell(cellIndex++);
                    cell.setCellValue(row.getOrDefault(key, "").toString());
                }
            }

            // 写入到文件
            try (FileOutputStream outputStream = new FileOutputStream(filePath)) {
                workbook.write(outputStream);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

}
