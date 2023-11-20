package com.ecnu.example;

import com.ecnu.common.APIConfig;
import com.ecnu.OAuth2Client;
import com.ecnu.common.OAuth2Config;
import com.ecnu.example.entity.FakeWithTS;
import com.ecnu.model.SyncToDBRequest;
import org.hibernate.HibernateException;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.cfg.Configuration;

import java.util.HashMap;

/**
 * @description Sync To Database Example
 */

public class SyncToDBExample {
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

        // -------初始化数据库配置----------
        // 创建Hibernate核心类，读取配置文件
        // hibernate.cfg.xml配置文件参考https://hibernate.net.cn/docs/14.html
        Configuration configuration = new Configuration().configure("hibernate.cfg.xml");
        //创建session工厂
        SessionFactory sf = null;
        try {
            sf = configuration.buildSessionFactory();
        } catch (HibernateException e) {
            throw new RuntimeException(e);
        }
        //获取session
        Session session = sf.openSession();

        // ---------全量同步，以组织机构接口同步为例------------
        // 初始化API配置
        String apiPath = "/api/v1/sync/fakewithts";
        HashMap<String, Object> param = new HashMap<>();
        param.put("ts", "0");
        APIConfig apiConfig = new APIConfig(apiPath, 2000, 100, null, param);
        SyncToDBRequest request = new SyncToDBRequest(apiConfig, FakeWithTS.class, session);
        // 如果接口不支持软删除标记，且需要删除上游已删除的数据，可以先删除表，再全量同步
        // 如果希望自己在同步时建立软删除标记，可以建立临时表进行全量同步
        // 再将临时表的数据更新到主表，并对比数据建立软删除标记。
        try {
            // 首次同步时，添加参数 ts=0，同步当前全部有效数据
            // 如果未创建表会自动根据 model 建表
            Integer count = client.syncToDB(request);
            System.out.println("DB：首次同步，从接口获取到" + count + "条数据");

            param.put("ts", "1672675200");
            param.put("full", "1");
            Integer count1 = client.syncToDB(new SyncToDBRequest(apiConfig, FakeWithTS.class, session));
            System.out.println("DB：增量同步，从接口获取到" + count1 + "条数据");
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            // 释放资源
            session.close();
            sf.close();
        }
    }
}
