package com.ecnu.example;

import com.ecnu.common.APIConfig;
import com.ecnu.OAuth2Client;
import com.ecnu.common.OAuth2Config;
import com.ecnu.example.entity.FakeWithTS;
import com.ecnu.model.SyncToModelRequest;

import java.util.HashMap;
import java.util.List;

/**
 * @description sync to model Example
 */

public class SyncToModelExample {
    public static void main(String[] args) throws Exception {
    /*
    public class OAuth2Config implements Serializable {
        private String clientId; // 必须
        private String clientSecret; // 必须
        private String baseUrl; // 默认 https://api.ecnu.edu.cn
        private List<String> scopes; //默认 ["ECNU-Basic"]
        private Integer timeout;//默认10秒
        private Boolean debug;//默认 false, 如果开启 debug，会打印出请求和响应的详细信息，对于数据同步类接口而言可能会非常大
    }
     */
        OAuth2Config cf = new OAuth2Config();
        cf.setClientId("your_client_id");
        cf.setClientSecret("your_client_secret");
        OAuth2Client client = OAuth2Client.getClient();
        client.initOAuth2ClientCredentials(cf);
        String apiPath = "/api/v1/sync/fakewithts";
        // --------------全量同步------------------
        // 添加参数
        HashMap<String, Object> param = new HashMap<>();
        param.put("ts", "0");
        APIConfig apiConfig = new APIConfig(apiPath, 2000, null, null, param);
        List<FakeWithTS> fakeRows = client.syncToModel(new SyncToModelRequest(apiConfig, FakeWithTS.class));
        // 使用同步后的model进行后续的操作
        System.out.println("Model: 全量同步" + fakeRows.size() + "条数据");

        // --------------增量同步------------------
        param.put("ts", "1672675200");
        param.put("full", "1");
        List<FakeWithTS> fakeRows1 = client.syncToModel(new SyncToModelRequest(apiConfig, FakeWithTS.class));
        System.out.println("Model: 增量同步" + fakeRows1.size() + "条数据");
    }
}
