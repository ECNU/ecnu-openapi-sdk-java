package com.ecnu.example;

import com.ecnu.OAuth2Client;
import com.ecnu.common.ApiConfig;
import com.ecnu.common.OAuth2Config;
import com.ecnu.example.entity.FakeWithTS;

import java.util.HashMap;
import java.util.List;

/**
 * @description sync to model Example
 */

public class SyncToModelExample {
    public static void main(String[] args) {
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
        List<FakeWithTS> fakeRows = client.syncToModel(config);
        // 使用同步后的model进行后续的操作
        System.out.println("Model: 全量同步" + fakeRows.size() + "条数据");

        // --------------增量同步------------------
        config = ApiConfig.builder()
                .apiPath("/api/v1/sync/fakewithts")
                .pageSize(100)
                .param(new HashMap<String, Object>() {{
                    put("ts", 1672675200);
                }})
                .build();
        fakeRows = client.syncToModel(config);
        System.out.println("Model: 增量同步" + fakeRows.size() + "条数据");
    }
}
