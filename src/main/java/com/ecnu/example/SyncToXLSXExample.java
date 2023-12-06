package com.ecnu.example;

import com.ecnu.OAuth2Client;
import com.ecnu.common.ApiConfig;
import com.ecnu.common.OAuth2Config;

import java.util.HashMap;

/**
 * @description Sycn To CSV file Example
 */
public class SyncToXLSXExample {
    public static void main(String[] args) {
        OAuth2Config cf = OAuth2Config.builder()
                .clientId("clientId")
                .clientSecret("clientSecret")
                .build();
        OAuth2Client client = OAuth2Client.getClient();
        client.initOAuth2ClientCredentials(cf);

        ApiConfig config = ApiConfig.builder()
                .apiPath("/api/v1/synv/fake")
                .pageSize(100)
                .param(new HashMap<String, Object>() {{
                    put("ts", 0);
                }})
                .build();

        // -------test syncToCSV----------
        try {
            client.syncToXLSX(config, "test.xlsx");
        } catch (Exception e) {
            System.out.println("sync to csv failed:" + e.getMessage());
        }
    }
}
