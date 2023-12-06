package com.ecnu.example;

import com.ecnu.OAuth2Client;
import com.ecnu.common.ApiConfig;
import com.ecnu.common.OAuth2Config;
import com.ecnu.example.entity.FakeWithTS;
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
        OAuth2Config cf = OAuth2Config.builder()
                .clientId("clientId")
                .clientSecret("clientSecret")
                .build();
        OAuth2Client client = OAuth2Client.getClient();
        client.initOAuth2ClientCredentials(cf);

        // -------初始化数据库配置----------
        // 创建Hibernate核心类，读取配置文件
        // hibernate.cfg.xml配置文件参考https://hibernate.net.cn/docs/14.html
        Configuration configuration = new Configuration().configure("hibernate.cfg.xml");
        //创建session工厂
        SessionFactory sf;
        try {
            sf = configuration.buildSessionFactory();
        } catch (HibernateException e) {
            throw new RuntimeException(e);
        }
        //获取session
        Session session = sf.openSession();

        // ---------全量同步，以组织机构接口同步为例------------
        ApiConfig config = ApiConfig.builder()
                .apiPath("/api/v1/sync/fakewithts")
                .pageSize(100)
                .param(new HashMap<String, Object>() {{
                    put("ts", 0);
                }})
                .build();
        try {
            // 首次同步时，添加参数 ts=0，同步当前全部有效数据
            // 如果未创建表会自动根据 model 建表
            Integer count = client.syncToDB(config, session, FakeWithTS.class);
            System.out.println("DB：首次同步，从接口获取到" + count + "条数据");
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            // 释放资源
            session.close();
            sf.close();
        }
    }
}
