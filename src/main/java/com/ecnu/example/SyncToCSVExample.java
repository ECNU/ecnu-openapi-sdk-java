package com.ecnu.example;

import com.ecnu.common.APIConfig;
import com.ecnu.OAuth2Client;
import com.ecnu.common.OAuth2Config;
import com.ecnu.model.SyncToCSVRequest;

/**
 * @description Sycn To CSV file Example
 */
public class SyncToCSVExample {
    public static void main(String[] args) {
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

        // -------初始化API配置----------
        String csvFileName = "testCSV.csv";
        String apiPath = "/api/v1/sync/fake?rowNum=100";
        APIConfig apiConfig = new APIConfig(apiPath, 2000, null, null, null);

        // -------初始化SyncToCSVRequest对象----------
        SyncToCSVRequest request = new SyncToCSVRequest(csvFileName, apiConfig);

        // -------test syncToCSV----------
        try {
            client.syncToCSV(request);
        } catch (Exception e) {
            System.out.println("sync to csv failed:" + e.getMessage());
        }
    }
}
