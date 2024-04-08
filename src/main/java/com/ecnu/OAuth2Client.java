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

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;

import org.hibernate.Session;
import org.hibernate.Transaction;
import org.springframework.beans.BeanUtils;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.security.oauth2.client.DefaultOAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.resource.UserRedirectRequiredException;
import org.springframework.security.oauth2.client.token.DefaultAccessTokenRequest;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsResourceDetails;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.common.AuthenticationScheme;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.web.client.RestClientException;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.concurrent.TimeUnit;
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


    private ClientCredentialsResourceDetails resource;
    private AuthorizationCodeResourceDetails authCodeResource = new AuthorizationCodeResourceDetails();
    private OAuth2RestTemplate template;
    private DefaultOAuth2ClientContext context = new DefaultOAuth2ClientContext();
    private String userInfoUrl;
    private String redirectUrl;
    private String baseUrl = "";
    private Boolean debug = false;
    private Integer retryCount = 0;
    private Cache<String, String> stateCache;

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

    public void initOAuth2AuthorizationCode(OAuth2Config cf) {
        this.userInfoUrl = cf.getUserInfoUrl();
        authCodeResource.setClientId(cf.getClientId());
        authCodeResource.setClientSecret(cf.getClientSecret());
        authCodeResource.setScope(cf.getScopes());
        authCodeResource.setAccessTokenUri(cf.getAccessTokenUrl());
        authCodeResource.setUserAuthorizationUri(cf.getUserAuthUrl());
        this.redirectUrl = cf.getRedirectUrl();
        authCodeResource.setPreEstablishedRedirectUri(this.redirectUrl);
        this.template = new OAuth2RestTemplate(authCodeResource, this.context);

        SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory();
        requestFactory.setConnectTimeout(cf.getTimeout() * 1000);
        requestFactory.setReadTimeout(cf.getTimeout() * 1000);
        this.template.setRequestFactory(requestFactory);

        client.setTemplate(template);
        client.setDebug(cf.getDebug());

        stateCache = CacheBuilder.newBuilder()
                .expireAfterWrite(cf.getExpirationTime(), TimeUnit.MINUTES) // 设置写入后的过期时间
                .build();
    }


    public String generateRandomState() {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[16]; // 生成一个16字节的随机数
        random.nextBytes(bytes);
        return new BigInteger(1, bytes).toString(16); // 返回十六进制编码的字符串
    }

    public String getAuthorizationEndpoint(String state) {
        if (this.authCodeResource == null) {
            throw new IllegalStateException("OAuth2Client is not initialized");
        }
        stateCache.put(state, "");

        // 构建授权URL
        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(this.authCodeResource.getUserAuthorizationUri())
                .queryParam("response_type", "code")
                .queryParam("client_id", this.authCodeResource.getClientId())
                .queryParam("redirect_uri", this.authCodeResource.getPreEstablishedRedirectUri())
                .queryParam("state", state);  // 添加state参数;

        if (this.authCodeResource.getScope() != null && !this.authCodeResource.getScope().isEmpty()) {
            builder.queryParam("scope", String.join(" ", this.authCodeResource.getScope()));
        }

        return builder.toUriString();
    }



    public String getInfo(String code, String state) throws IOException {
        OAuth2AccessToken token = null;
        try {
            token = getToken(code, state);
        } catch (IllegalArgumentException e) {
            // 这里处理无效状态的情况，例如记录日志或抛出异常
            System.err.println("Invalid state: " + e.getMessage());
            throw new IOException("Invalid state provided", e);
        }
        return getUserInfo(token.getValue());
    }

    private OAuth2AccessToken getToken(String code, String state) throws IOException, UserRedirectRequiredException {
        if (stateCache.getIfPresent(state)==null) {
            System.err.println("Invalid state");
        }

        this.context.getAccessTokenRequest().setAuthorizationCode(code);
        this.context.getAccessTokenRequest().setPreservedState(this.redirectUrl);
        OAuth2AccessToken accessToken = null;
        try {
            accessToken = this.template.getAccessToken();
        } catch (RestClientException e) {
            System.err.println("Error while fetching access token: " + e.getMessage());
        } catch (Exception e) {
            System.err.println("An error occurred: " + e.getMessage());
        }
        return accessToken;
    }


    private String getUserInfo(String token) throws IOException {
        URL url = new URL(this.userInfoUrl);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestProperty("Authorization", "Bearer " + token);

        int responseCode = conn.getResponseCode();
        if (responseCode != 200) {
            throw new IOException("Failed to get user info");
        }

        ObjectMapper mapper = new ObjectMapper();
        try (InputStream is = conn.getInputStream()) {
            return readInputStream(is);
        }
    }
    private String readInputStream(InputStream inputStream) throws IOException {
        StringBuilder result = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream, StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                result.append(line);
            }
        }
        return result.toString();
    }

    private <T> EcnuDTO<EcnuPageDTO<T>> getData(String url) throws Exception {
        Boolean expired = isRenewToken();
        if (expired) {
            renewToken();
        }
        ParameterizedTypeReference<EcnuDTO<EcnuPageDTO<T>>> responseType = new ParameterizedTypeReference<EcnuDTO<EcnuPageDTO<T>>>() {
        };
        ResponseEntity<EcnuDTO<EcnuPageDTO<T>>> response = template.exchange(url, HttpMethod.GET, null, responseType);
        if (debug) {
            System.out.println(url);
            System.out.println(response.getStatusCode().value());
            System.out.println(response.getHeaders().toString());
        }
        String errorCode = response.getHeaders().getFirst("X-Ca-Error-Code");
        if (errorCode != null) {
            if (errorCode.equals(Constants.Invalid_Token_ERROR) && client.getRetryCount() <= 3) {
                retryAdd(client);
                return getData(url);
            } else {
                throw new Exception(response.getBody().getErrMsg());
            }
        } else {
            if (client.getRetryCount() > 0) {
                retryReset(client);
            }
        }
        return response.getBody();
    }

    private <T> EcnuDTO<EcnuPageDTO<T>> getData(ApiConfig apiConfig, int page) throws Exception {
        String queryParams = apiConfig.getParam().entrySet().stream()
                .map(entry -> entry.getKey() + "=" + entry.getValue())
                .collect(Collectors.joining("&"));
        String url = String.format("%s%s?pageNum=%s&pageSize=%s&%s", client.getBaseUrl(), apiConfig.getApiPath(), page, apiConfig.getPageSize(), queryParams);
        return getData(url);
    }

    private <T> List<T> getAllData(ApiConfig apiConfig) throws Exception {
        apiConfig.setDefault();
        List<T> list;
        int i = 1;
        //通过接口获取
        EcnuDTO<EcnuPageDTO<T>> result = getData(apiConfig, i);
        //判断状态码是否为0
        if (result.getErrCode() == 0) {
            //将查询到的数据存放入集合
            list = new ArrayList<>(result.getData().getRows());
            //通过while循环去获取每一页的数据,每一页数据100条
            while (i * result.getData().getPageSize() < result.getData().getTotalNum()) {
                i++;
                result = getData(apiConfig, i);
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

    public <T> List<T> callAPI(String url, String method, HashMap<String, Object> header, String data) throws Exception {
        switch (method) {
            case "GET":
                EcnuDTO<EcnuPageDTO<T>> result = getData(url);
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
    public <T> List<T> syncToModel(ApiConfig apiConfig) throws Exception {
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
            EcnuDTO<EcnuPageDTO<T>> result = getData(apiConfig, i);
            //判断状态码是否为0
            if (result.getErrCode() == 0) {
                //将查询到的数据存放入集合
                totalSaved += batchSyncToDB(session, apiConfig.getBatchSize(), result.getData().getRows(), model);
                //通过while循环去获取每一页的数据,每一页数据100条
                while (i * result.getData().getPageSize() < result.getData().getTotalNum()) {
                    i++;
                    result = getData(apiConfig, i);
                    if (result.getErrCode() == 0) {
                        totalSaved += batchSyncToDB(session, apiConfig.getBatchSize(), result.getData().getRows(), model);
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
        OAuth2AccessToken token = client.getTemplate().getAccessToken();
        if (token == null) return false;
        Date expirationDate = token.getExpiration();
        long currenTs = System.currentTimeMillis();
        long expirationTs = expirationDate.getTime();
        long remainTs = expirationTs - currenTs;
        return remainTs < 0 || (remainTs > 0 && remainTs < Constants.NEAR_EXPIRE_TIME);
    }

    private void renewToken() {
        ClientCredentialsResourceDetails resourceDetails = new ClientCredentialsResourceDetails();
        BeanUtils.copyProperties(client.getResource(), resourceDetails);
        resourceDetails.setGrantType("client_credentials");
        template = new OAuth2RestTemplate(resourceDetails);
        OAuth2AccessToken newToken = template.getAccessToken();
        template.getOAuth2ClientContext().setAccessToken(newToken);
    }

}
