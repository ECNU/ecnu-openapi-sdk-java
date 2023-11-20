package com.ecnu.example;

import com.ecnu.OAuth2Client;
import com.ecnu.common.APIConfig;
import com.ecnu.common.OAuth2Config;
import com.ecnu.example.entity.Fake;
import com.ecnu.model.SyncToDBRequest;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.cfg.Configuration;

import java.util.Scanner;

public class TestDB {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("请输入totalNum:");
        int totalNum = scanner.nextInt();
        System.out.println("请输入batchSize:");
        int batchSize = scanner.nextInt();
        test(totalNum, batchSize);
    }

    private static void test(int totolNum, int batchSize) {
        OAuth2Config cf = new OAuth2Config();
        cf.setClientId("your_client_id");
        cf.setClientSecret("your_client_secret");
        OAuth2Client client = OAuth2Client.getClient();
        client.initOAuth2ClientCredentials(cf);

        Configuration configuration = new Configuration().configure("hibernate.cfg.xml");
        //创建session工厂
        SessionFactory sf = configuration.buildSessionFactory();
        ;
        //获取session
        Session session = sf.openSession();

        // ---------全量同步，以组织机构接口同步为例------------
        // 初始化API配置
        String apiPath = "/api/v1/sync/fake?totalNum=" + totolNum;
        APIConfig apiConfigForFull = new APIConfig(apiPath, 2000, batchSize, null, null);
        SyncToDBRequest requestForAll = new SyncToDBRequest(apiConfigForFull, Fake.class, session);
        try {
            // 实体类配置文件参考Fake.hbm.xml
            long begin = System.currentTimeMillis();
            Integer res = client.syncToDB(requestForAll);
            long end = System.currentTimeMillis();
            System.out.println("sync to DB " + totolNum + "条数据，batchSize为" + batchSize + "时，花费时间为：" + (double) (end - begin) / 1000.0 + "秒");
            Runtime runtime = Runtime.getRuntime();
            long totalMemory = runtime.totalMemory(); // 获取总内存量
            long freeMemory = runtime.freeMemory(); // 获取空闲内存量
            long usedMemory = totalMemory - freeMemory; // 计算已使用的内存量
            System.out.println("Total Memory: " + totalMemory / 1024 / 1024 + "MB");
            System.out.println("Free Memory: " + freeMemory / 1024 / 1024 + "MB");
            System.out.println("Used Memory: " + usedMemory / 1024 / 1024 + "MB");
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            // 释放资源
            session.close();
            sf.close();
        }
    }
}
