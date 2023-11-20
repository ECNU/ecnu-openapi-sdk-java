package com.ecnu.model;

import com.ecnu.common.APIConfig;
import lombok.Data;

/**
 * @author lc
 * @create 2023/10/17-15:20
 * @description
 */

@Data
public class SyncToCSVRequest {
    private String csvFileName;

    private APIConfig apiConfig;

    public SyncToCSVRequest() {
    }

    public SyncToCSVRequest(String csvFileName, APIConfig apiConfig) {
        this.csvFileName = csvFileName;
        this.apiConfig = apiConfig;
    }
}
