package com.ecnu.example;

import com.alibaba.fastjson.JSONObject;
import com.ecnu.OAuth2Client;
import com.ecnu.common.ApiConfig;
import com.ecnu.common.OAuth2Config;

import java.util.HashMap;
import java.util.List;

/**
 * @description CallAPI Example
 */
public class CallAPIExample {
    public static void main(String[] args) throws Exception {
        OAuth2Config cf = OAuth2Config.builder()
                .clientId("clientId")
                .clientSecret("clientSecret")
                .build();
        OAuth2Client client = OAuth2Client.getClient();
        client.initOAuth2ClientCredentials(cf);

        ApiConfig config = ApiConfig.builder()
                .apiPath("/api/v1/sync/fakewithts")
                .pageSize(100)
                .param(new HashMap<String, Object>() {{
                    put("ts", 0);
                }})
                .build();

        // -------test callApi----------
        List<JSONObject> reponse = client.getAllData(config);
        if (reponse != null) {
            System.out.println(reponse);
        } else {
            System.out.println("callAPI failed!");
        }

    }
}
