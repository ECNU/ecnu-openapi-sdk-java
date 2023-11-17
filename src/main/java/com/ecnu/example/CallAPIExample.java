package com.ecnu.example;

import com.alibaba.fastjson.JSONObject;
import com.ecnu.OAuth2Client;
import com.ecnu.common.OAuth2Config;
import com.ecnu.model.CallAPIRequest;

/**
 * @description CallAPI Example
 */
public class CallAPIExample {
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
        // -------初始化client配置----------
        OAuth2Config cf = new OAuth2Config();
        cf.setClientId("your_client_id");
        cf.setClientSecret("your_client_secret");
        OAuth2Client client = OAuth2Client.getClient();
        client.initOAuth2ClientCredentials(cf);

        // -------初始化CallAPIRequest对象----------
        String url = "https://api.ecnu.edu.cn/api/v1/sync/fakewithts?ts=0&pageNum=1&pageSize=1";
        CallAPIRequest callAPIRequest = new CallAPIRequest(url, "GET", null, null);

        // -------test callApi----------
        JSONObject reponse = client.callAPI(callAPIRequest);
        if (reponse != null) {
            System.out.println(reponse);
        } else {
            System.out.println("callAPI failed!");
        }

    }
}
