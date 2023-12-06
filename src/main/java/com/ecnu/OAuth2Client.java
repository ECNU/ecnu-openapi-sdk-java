package com.ecnu;

import com.alibaba.fastjson.JSONObject;
import com.ecnu.common.ApiConfig;
import com.ecnu.common.EcnuDTO;
import com.ecnu.common.EcnuPageDTO;
import com.ecnu.common.OAuth2Config;
import com.ecnu.util.CSVUtils;
import com.ecnu.util.Constants;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.type.CollectionType;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import lombok.Data;
import org.hibernate.Session;
import org.hibernate.Transaction;
import org.springframework.beans.BeanUtils;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.security.oauth2.client.DefaultOAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsResourceDetails;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;


/**
 * @author lc
 * @create 2023/10/13-17:05
 * @description
 */

@Data
public class OAuth2Client {

    private ClientCredentialsResourceDetails resource;
    private OAuth2RestTemplate template;
    private String baseUrl = "";
    private Boolean debug = false;

    private static volatile OAuth2Client client = getClient();

    public static OAuth2Client getClient() {
        if (client == null) {
            synchronized (OAuth2Client.class) {
                if (client == null) {
                    client = new OAuth2Client();
                }
            }
        }
        return client;
    }

    /**
     * 指定配置，初始化client
     *
     * @param cf
     */

    public void initOAuth2ClientCredentials(OAuth2Config cf) {
        // 创建OAuth2 client
        ClientCredentialsResourceDetails resource = new ClientCredentialsResourceDetails();
        resource.setClientId(cf.getClientId());
        resource.setClientSecret(cf.getClientSecret());
        resource.setScope(cf.getScopes());
        resource.setAccessTokenUri(cf.getBaseUrl() + "/oauth2/token");
        // 创建OAuth2RestTemplate
        OAuth2RestTemplate template = new OAuth2RestTemplate(resource, new DefaultOAuth2ClientContext());
        // 设置连接超时和读取超时
        SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory();
        requestFactory.setConnectTimeout(cf.getTimeout() * 1000);
        requestFactory.setReadTimeout(cf.getTimeout() * 1000);
        template.setRequestFactory(requestFactory);
        client.setResource(resource);
        client.setTemplate(template);
        client.setBaseUrl(cf.getBaseUrl());
        client.setDebug(cf.getDebug());
    }

    private <T> EcnuDTO<EcnuPageDTO<T>> getData(String url, long ts, int page, int size) {
        Boolean expired = isRenewToken(client);
        if (expired) {
            renewToken(client);
        }
        url = String.format("%s%s?ts=%s&pageNum=%s&pageSize=%s", client.getBaseUrl(), url, ts, page, size);
        ParameterizedTypeReference<EcnuDTO<EcnuPageDTO<T>>> responseType =
                new ParameterizedTypeReference<EcnuDTO<EcnuPageDTO<T>>>() {
                };
        ResponseEntity<EcnuDTO<EcnuPageDTO<T>>> response = template.exchange(
                url, HttpMethod.GET, null, responseType);
        return response.getBody();
    }

    public <T> List<T> getAllData(ApiConfig apiConfig) {
        apiConfig.setDefault();
        List<T> list = new ArrayList<>();
        int i = 1;
        //通过接口获取
        long ts = Long.valueOf((Integer) apiConfig.getParam().getOrDefault("ts", 0));
        EcnuDTO<EcnuPageDTO<T>> result = getData(apiConfig.getApiPath(), ts, i, apiConfig.getPageSize());
        //判断状态码是否为0
        if (result.getErrCode() == 0) {
            //将查询到的数据存放入集合
            list.addAll(result.getData().getRows());
            //通过while循环去获取每一页的数据,每一页数据100条
            while (i * result.getData().getPageSize() < result.getData().getTotalNum()) {
                i++;
                result = getData(apiConfig.getApiPath(), ts, i, apiConfig.getPageSize());
                if (result.getErrCode() == 0) list.addAll(result.getData().getRows());
            }
        }
        return list;
    }

    /**
     * 接口数据同步到csv文件
     *
     * @return
     * @throws Exception
     */
    public void syncToCSV(ApiConfig apiConfig, String csvFileName) throws Exception {
        List<JSONObject> allRows = getAllData(apiConfig);
        try {
            CSVUtils.writeJSONToCSV(allRows, csvFileName);
        } catch (Exception e) {
            throw new Exception("write rows to csv failed!" + e.getMessage());
        }
    }

    public void syncToXLSX(ApiConfig apiConfig, String xlsxFileName) throws Exception {
        List<JSONObject> allRows = getAllData(apiConfig);
        try {
            CSVUtils.writeJSONToXLSX(allRows, xlsxFileName);
        } catch (Exception e) {
            throw new Exception("write rows to csv failed!" + e.getMessage());
        }
    }

    /**
     * 接口数据同步为模型
     *
     * @param <T>
     * @return
     */
    public <T> List<T> syncToModel(ApiConfig apiConfig) {
        return getAllData(apiConfig);
    }

    /**
     * 接口数据同步到数据库
     *
     * @param <T>
     * @return 成功插入条数
     * @throws Exception
     */

    public <T> Integer syncToDB(ApiConfig apiConfig, Session session, Class model) throws Exception {
        Transaction tx = session.getTransaction();
        Integer totalSaved = 0;
        try {
            if (tx == null || !tx.isActive()) {
                tx = session.beginTransaction();
            }
            // 将上述列表中的对象插入数据库中
            apiConfig.setDefault();
            int i = 1;
            //通过接口获取
            long ts = Long.valueOf((Integer) apiConfig.getParam().getOrDefault("ts", 0));
            EcnuDTO<EcnuPageDTO<T>> result = getData(apiConfig.getApiPath(), ts, i, apiConfig.getPageSize());
            //判断状态码是否为0
            if (result.getErrCode() == 0) {
                //将查询到的数据存放入集合
                totalSaved += batchSyncToDB(session, apiConfig.getBatchSize(), result.getData().getRows(), model);
                //通过while循环去获取每一页的数据,每一页数据100条
                while (i * result.getData().getPageSize() < result.getData().getTotalNum()) {
                    i++;
                    result = getData(apiConfig.getApiPath(), ts, i, apiConfig.getPageSize());
                    if (result.getErrCode() == 0) {
                        totalSaved += batchSyncToDB(session, apiConfig.getBatchSize(), result.getData().getRows(), model);
                    }
                }
            }
            tx.commit();
        } catch (Exception e) {
            if (tx != null && tx.isActive()) {
                // 若插入时出现异常，则回滚
                tx.rollback();
                throw new Exception("insert failed: " + e.getMessage());
            }
        }
        return totalSaved;
    }

    /**
     * 批量写入数据库
     *
     * @param session
     * @param batchSize
     * @param modelList
     * @return
     */

    private <T> Integer batchSyncToDB(Session session, Integer batchSize, List<T> modelList, Class model) throws Exception {
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.registerModule(new JavaTimeModule());
        CollectionType javaType = objectMapper.getTypeFactory().constructCollectionType(List.class, model);
        List<T> modelsPerPage = objectMapper.readValue(objectMapper.writeValueAsString(modelList), javaType);
        int successfulSave = 0;
        try {
            for (int i = 0; i < modelsPerPage.size(); i++) {
                // 针对主键进行查询，若存在，则更新；反之插入
                session.saveOrUpdate(modelsPerPage.get(i));
                successfulSave++;
                if (i % batchSize == 0) {
                    session.flush(); // 刷新缓存
                    session.clear(); // 清空缓存
                }
            }
            return successfulSave;
        } catch (Exception e) {
            throw new Exception();
        }
    }

    /**
     * 判断当前token是否失效，以及剩余有效时间
     *
     * @param client
     * @return 失效：返回负数；未失效，返回正数，剩余时间
     */

    private Boolean isRenewToken(OAuth2Client client) {
        OAuth2AccessToken token = client.getTemplate().getAccessToken();
        if (token == null) return false;
        Date expirationDate = token.getExpiration();
        long currenTs = System.currentTimeMillis();
        long expirationTs = expirationDate.getTime();
        long remainTs = expirationTs - currenTs;
        return remainTs < 0 || (remainTs > 0 && remainTs < Constants.NEAR_EXPIRE_TIME);
    }

    private void renewToken(OAuth2Client client) {
        OAuth2RestTemplate template = client.getTemplate();
        OAuth2AccessToken accessToken = template.getAccessToken();
        ClientCredentialsResourceDetails cf = client.getResource();
        if (accessToken.isExpired()) {
            // 已过期，获取新的token
            ClientCredentialsResourceDetails resourceDetails = new ClientCredentialsResourceDetails();
            BeanUtils.copyProperties(cf, resourceDetails);
            resourceDetails.setGrantType("client_credentials");
            OAuth2RestTemplate template1 = new OAuth2RestTemplate(resourceDetails);
            OAuth2AccessToken newToken = template1.getAccessToken();
            template.getOAuth2ClientContext().setAccessToken(newToken);
        } else {
            // 未过期
            Date newExpirationDate = new Date(accessToken.getExpiration().getTime() + Constants.DEFAULT_TOKEN_DURATION);
            DefaultOAuth2AccessToken newToken = new DefaultOAuth2AccessToken(accessToken);
            newToken.setExpiration(newExpirationDate);
            template.getOAuth2ClientContext().setAccessToken(newToken);
        }
    }
}
