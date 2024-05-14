package com.ecnu;

import com.alibaba.fastjson.JSONObject;
import com.ecnu.common.ApiConfig;
import com.ecnu.common.EcnuDTO;
import com.ecnu.common.EcnuPageDTO;
import com.ecnu.common.OAuth2Config;
import com.ecnu.util.CSVUtils;
import com.ecnu.util.Constants;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.type.CollectionType;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.github.scribejava.core.builder.ScopeBuilder;
import com.github.scribejava.core.builder.ServiceBuilder;
import com.github.scribejava.core.builder.api.DefaultApi20;
import com.github.scribejava.core.model.OAuth2AccessToken;
import com.github.scribejava.core.model.OAuthRequest;
import com.github.scribejava.core.model.Response;
import com.github.scribejava.core.model.Verb;
import com.github.scribejava.core.oauth.OAuth20Service;
import lombok.Data;
import org.hibernate.Session;
import org.hibernate.Transaction;

import java.io.IOException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.stream.Collectors;


/**
 * @author lc
 * @create 2023/10/13-17:05
 * @description
 */

@Data
public class OAuth2Client {

    private OAuth20Service service;
    private OAuth2AccessToken accessToken;
    private Instant expiryTime;
    private String baseUrl = "";
    private Boolean debug = false;
    private Integer retryCount = 0;
    private static final ObjectMapper mapper = new ObjectMapper();

    private static volatile OAuth2Client client = getClient();

    public static OAuth2Client getClient() {
        if (client == null) {
            synchronized (OAuth2Client.class) {
                if (client == null) {
                    client = new OAuth2Client();
                    mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
                    mapper.registerModule(new JavaTimeModule());
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
        DefaultApi20 api20 = new DefaultApi20() {
            @Override
            public String getAccessTokenEndpoint() {
                return cf.getBaseUrl() + "/oauth2/token";
            }

            @Override
            protected String getAuthorizationBaseUrl() {
                return cf.getBaseUrl();
            }
        };
        OAuth20Service service = new ServiceBuilder(cf.getClientId())
                .apiSecret(cf.getClientSecret())
                .defaultScope(new ScopeBuilder().withScopes(cf.getScopes()))
                .build(api20);
        client.setService(service);
        client.setBaseUrl(cf.getBaseUrl());
        client.setDebug(cf.getDebug());
    }

    private <T> EcnuDTO<EcnuPageDTO<T>> getData(String url, Class<T> clazz) throws Exception {
        Boolean expired = isRenewToken();
        if (expired) {
            renewToken();
        }

        OAuthRequest request = new OAuthRequest(Verb.GET, url);
        service.signRequest(accessToken, request);
        Response response = service.execute(request);
        if (debug) {
            System.out.println(url);
            System.out.println(response.getCode());
            System.out.println(response.getHeaders().toString());
        }
        String errorCode = response.getHeaders().get("X-Ca-Error-Code");
        if (errorCode != null) {
            if (errorCode.equals(Constants.Invalid_Token_ERROR) && client.getRetryCount() <= 3) {
                retryAdd(client);
                return getData(url, clazz);
            } else {
                throw new Exception(response.getBody());
            }
        } else {
            if (client.getRetryCount() > 0) {
                retryReset(client);
            }
        }
        return mapper.readValue(response.getBody(), mapper.getTypeFactory().constructParametricType(EcnuDTO.class, mapper.getTypeFactory().constructParametricType(EcnuPageDTO.class, clazz)));
    }

    private <T> EcnuDTO<EcnuPageDTO<T>> getData(ApiConfig apiConfig, int page, Class<T> clazz) throws Exception {
        String queryParams = apiConfig.getParam().entrySet().stream()
                .map(entry -> entry.getKey() + "=" + entry.getValue())
                .collect(Collectors.joining("&"));
        String url = String.format("%s%s?pageNum=%s&pageSize=%s&%s", client.getBaseUrl(), apiConfig.getApiPath(), page, apiConfig.getPageSize(), queryParams);
        return getData(url, clazz);
    }

    private <T> List<T> getAllData(ApiConfig apiConfig, Class<T> clazz) throws Exception {
        apiConfig.setDefault();
        List<T> list;
        int i = 1;
        //通过接口获取
        EcnuDTO<EcnuPageDTO<T>> result = getData(apiConfig, i, clazz);
        //判断状态码是否为0
        if (result.getErrCode() == 0) {
            //将查询到的数据存放入集合
            list = new ArrayList<>(result.getData().getRows());
            //通过while循环去获取每一页的数据,每一页数据100条
            while (i * result.getData().getPageSize() < result.getData().getTotalNum()) {
                i++;
                result = getData(apiConfig, i, clazz);
                if (result.getErrCode() == 0) {
                    list.addAll(result.getData().getRows());
                } else {
                    throw new Exception(result.getErrMsg());
                }
            }
        } else {
            throw new Exception(result.getErrMsg());
        }
        return list;
    }

    private void retryAdd(OAuth2Client client) {
        ReadWriteLock lock = new ReentrantReadWriteLock();
        lock.readLock().lock();
        try {
            client.setRetryCount(client.getRetryCount() + 1);
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            lock.readLock().unlock();
        }
    }

    private void retryReset(OAuth2Client client) {
        ReadWriteLock lock = new ReentrantReadWriteLock();
        lock.readLock().lock();
        try {
            client.setRetryCount(0);
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            lock.readLock().unlock();
        }
    }

    public <T> List<T> callAPI(String url, String method, HashMap<String, Object> header, String data, Class<T> clazz) throws Exception {
        switch (method) {
            case "GET":
                EcnuDTO<EcnuPageDTO<T>> result = getData(url, clazz);
                if (result.getErrCode() == 0) {
                    return result.getData().getRows();
                } else {
                    throw new Exception(result.getErrMsg());
                }
            default:
                throw new Exception("this method is not supported");
        }
    }

    /**
     * 接口数据同步到csv文件
     *
     * @return
     * @throws Exception
     */
    public void syncToCSV(ApiConfig apiConfig, String csvFileName) throws Exception {
        List<JSONObject> allRows = getAllData(apiConfig, JSONObject.class);
        try {
            CSVUtils.writeJSONToCSV(allRows, csvFileName);
        } catch (Exception e) {
            throw new Exception("write rows to csv failed!" + e.getMessage());
        }
    }

    public void syncToXLSX(ApiConfig apiConfig, String xlsxFileName) throws Exception {
        List<JSONObject> allRows = getAllData(apiConfig, JSONObject.class);
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
    public <T> List<T> syncToModel(ApiConfig apiConfig, Class<T> clazz) throws Exception {
        return getAllData(apiConfig, clazz);
    }

    /**
     * 接口数据同步到数据库
     *
     * @param <T>
     * @return 成功插入条数
     * @throws Exception
     */

    public <T> Integer syncToDB(ApiConfig apiConfig, Session session, Class<T> clazz) throws Exception {
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
            EcnuDTO<EcnuPageDTO<T>> result = getData(apiConfig, i, clazz);
            //判断状态码是否为0
            if (result.getErrCode() == 0) {
                //将查询到的数据存放入集合
                totalSaved += batchSyncToDB(session, apiConfig.getBatchSize(), result.getData().getRows(), clazz);
                //通过while循环去获取每一页的数据,每一页数据100条
                while (i * result.getData().getPageSize() < result.getData().getTotalNum()) {
                    i++;
                    result = getData(apiConfig, i, clazz);
                    if (result.getErrCode() == 0) {
                        totalSaved += batchSyncToDB(session, apiConfig.getBatchSize(), result.getData().getRows(), clazz);
                    } else {
                        throw new Exception(result.getErrMsg());
                    }
                }
            } else {
                throw new Exception(result.getErrMsg());
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

    private <T> Integer batchSyncToDB(Session session, Integer batchSize, List<T> modelList, Class model) throws
            Exception {
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
     * @return 失效：返回负数；未失效，返回正数，剩余时间
     */

    private Boolean isRenewToken() {
        if (expiryTime == null) {
            return true;
        }
        return Instant.now().isAfter(expiryTime);
    }

    private void renewToken() throws IOException, ExecutionException, InterruptedException {
        OAuth2AccessToken token = service.getAccessTokenClientCredentialsGrant();
        expiryTime = Instant.now().plus(token.getExpiresIn(), ChronoUnit.SECONDS);
        accessToken = token;
    }

}
