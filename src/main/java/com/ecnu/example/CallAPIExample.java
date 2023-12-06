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
        /*
        public class OAuth2Config {
            private String clientId; // 必须
            private String clientSecret; // 必须
            private String baseUrl; // 默认 https://api.ecnu.edu.cn
            private List<String> scopes; //默认 ["ECNU-Basic"]
            private Integer timeout; //默认10秒
            private Boolean debug; //默认 false, 如果开启 debug，会打印出请求和响应的详细信息，对于数据同步类接口而言可能会非常大
        }
        */
        OAuth2Config cf = OAuth2Config.builder()
                .clientId("clientId")
                .clientSecret("clientSecret")
                .debug(true)
                .build();
        OAuth2Client client = OAuth2Client.getClient();
        client.initOAuth2ClientCredentials(cf);

        String url = "https://api.ecnu.edu.cn/api/v1/sync/fakewithts?ts=0&pageNum=1&pageSize=1";

        // -------test callApi----------
        List<JSONObject> response = client.callAPI(url, "GET", null, null);
        if (response != null) {
            System.out.println(response);
        } else {
            System.out.println("callAPI failed!");
        }

    }
}
