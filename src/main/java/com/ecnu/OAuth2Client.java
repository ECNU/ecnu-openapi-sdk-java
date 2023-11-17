package com.ecnu;

import com.alibaba.fastjson.JSONObject;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.type.CollectionType;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.google.gson.Gson;
import com.ecnu.common.APIConfig;
import com.ecnu.common.APIResult;
import com.ecnu.common.DataResult;
import com.ecnu.common.OAuth2Config;
import com.ecnu.constants.Constants;
import com.ecnu.model.CallAPIRequest;
import com.ecnu.model.SyncToCSVRequest;
import com.ecnu.model.SyncToDBRequest;
import com.ecnu.model.SyncToModelRequest;
import lombok.Data;
import org.hibernate.Session;
import org.hibernate.Transaction;
import org.springframework.beans.BeanUtils;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.security.oauth2.client.DefaultOAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsResourceDetails;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.*;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import static com.ecnu.constants.Constants.*;

/**
 * @author lc
 * @create 2023/10/13-17:05
 * @description
 */

@Data

public class OAuth2Client {

    private ClientCredentialsResourceDetails resource;
    private OAuth2RestTemplate template;
    private String baseUrl = DEFAULT_BASE_URL;
    private Integer retryCount = 0;
    private Boolean debug = false;

    // 单例模式，线程安全
    private OAuth2Client() {
    }

    private static OAuth2Client client = getClient();

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
     * @param cf
     */

    public void initOAuth2ClientCredentials (OAuth2Config cf) {
        List<String> scopes = new ArrayList<>();
        scopes.add(Constants.DEFAULT_SCOPE);
        Integer timeout = Constants.DEFAULT_TIMEOUT;
        if (cf.getBaseUrl() != null && !cf.getBaseUrl().equals("")) {
            baseUrl = cf.getBaseUrl();
        }
        if (cf.getScopes() != null && cf.getScopes().size() > 0) {
            scopes = cf.getScopes();
        }
        if (cf.getTimeout() != null && cf.getTimeout() > 0) {
            timeout = cf.getTimeout();
        }
        if (cf.getDebug() != null) {
            debug = cf.getDebug();
        }
        // 创建OAuth2 client
        ClientCredentialsResourceDetails resource = new ClientCredentialsResourceDetails();
        resource.setClientId(cf.getClientId());
        resource.setClientSecret(cf.getClientSecret());
        resource.setScope(scopes);
        resource.setAccessTokenUri(baseUrl + "/oauth2/token");
        // 创建OAuth2RestTemplate
        OAuth2RestTemplate template = new OAuth2RestTemplate(resource, new DefaultOAuth2ClientContext());
        // 设置连接超时和读取超时
        SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory();
        requestFactory.setConnectTimeout(timeout * 1000);
        requestFactory.setReadTimeout(timeout * 1000);
        template.setRequestFactory(requestFactory);
        client.setResource(resource);
        client.setTemplate(template);
        client.setBaseUrl(baseUrl);
        client.setDebug(debug);
    }

    /**
     * 返回接口row数据
     * @param request
     * @return
     * @throws Exception
     */

    public JSONObject callAPI(CallAPIRequest request) throws Exception {
        // 调用方法前确认是否续约token
        Boolean expired = isRenewToken(client);
        if (expired) {
            renewToken(client);
        }
        String url = request.getUrl();
        String method = request.getMethod();
        switch (method) {
            case "GET":
                return HttpGet(client.getTemplate(), url);
            default:
                throw new Exception("this method is not supported");
        }
    }
    private JSONObject HttpGet(OAuth2RestTemplate template, String url) {
        APIResult apiResult;
        try {
            ResponseEntity<JSONObject> response = template.getForEntity(url, JSONObject.class);
            apiResult = parseApiResult(response, url, client.getDebug());
            String errorCode = response.getHeaders().getFirst("X-Ca-Error-Code");
            if (errorCode != null) {
                if (errorCode.equals(Invalid_Token_ERROR) && client.getRetryCount() <= 3) {
                    retryAdd(client);
                    OAuth2RestTemplate tmpTemplate = new OAuth2RestTemplate(client.getResource());
                    return HttpGet(tmpTemplate, url);
                } else {
                    return null;
                }
            } else {
                if (client.getRetryCount() > 0) {
                    retryReset(client);
                }
            }
            if (apiResult.getErrCode() != 0) {
                apiResult = null;
                throw new Exception(apiResult.getErrMsg());
            }
        } catch (Exception e) {
            apiResult = null;
            e.printStackTrace();
        }
        return apiResult == null ? null : apiResult.getData();
    }

    private APIResult parseApiResult(ResponseEntity<JSONObject> response, String url, Boolean debug) throws Exception {
        APIResult apiResult = new APIResult();
        String requestId = response.getHeaders().getFirst("X-Ca-Request-Id");
        Integer errCode = response.getBody().getInteger("errCode");
        String errMsg = response.getBody().getString("errMsg");
        if (response.getHeaders() == null) {
            throw new Exception("request fail");
        }
        if (debug) {
            System.out.println(url);
            System.out.println(response.getStatusCode().value());
            System.out.println(response.getHeaders().toString());
        }
        if (response.getStatusCode().value() != 200) {
            String eCode = response.getHeaders().getFirst("X-Ca-Error-Code");
            String eMessage = response.getHeaders().getFirst("X-Ca-Error-Message");
            apiResult.setErrCode(response.getStatusCode().value());
            //错误码：A401OT，表示非法access_token
            if (eCode.equals(Invalid_Token_ERROR)) {
                throw new Exception(Invalid_Token_ERROR);
            } else {
                apiResult.setErrMsg(eMessage);
                throw new Exception("invoke api get fail, X-Ca-Error-Code:" + eCode + ", X-Ca-Error-Message:" + eMessage + ",X-Ca-Request-Id:" + requestId);
            }
        }
        if (response.getBody() == null) {
            throw new Exception("api response body is null");
        }
        if (debug) {
            System.out.println(response.getBody().toString());
        }
        apiResult.setRequestId(requestId);
        apiResult.setErrCode(errCode);
        apiResult.setErrMsg(errMsg);
        apiResult.setData(response.getBody().getJSONObject("data"));
        return apiResult;
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

    /**
     * 获得allAows之前的通用操作
     */
    public String basicOperation(APIConfig apiConfig) throws Exception {
        // 1.判断TOKEN是否需要续约
        Boolean expired = isRenewToken(client);
        if (expired) {
            renewToken(client);
        }
        apiConfig.setDefault();
        // 2.拼接请求
        String url;
        if (apiConfig.getAPIPath().contains("?")) {
            // 拼接pageNum放到getRows中
            url = client.getBaseUrl() + apiConfig.getAPIPath() + "&pageSize=" + apiConfig.getPageSize();
        } else {
            url = client.getBaseUrl() + apiConfig.getAPIPath() + "?pageSize=" + apiConfig.getPageSize();
        }
        return addPamaToUrl(url, apiConfig);
    }

    /**
     * 接口数据同步到csv文件
     * @param request
     * @return
     * @throws Exception
     */
    public void syncToCSV (SyncToCSVRequest request) throws Exception {
        APIConfig apiConfig = request.getApiConfig();
        String csvFileName = request.getCsvFileName();
        String url = basicOperation(apiConfig);
        List<JSONObject> allRows = getAllRows(url);
        if (allRows == null) {
            throw new Exception("get all rows failed!");
        }
        try {
            writeRowsToCSV(allRows, csvFileName);
        } catch (Exception e) {
            throw new Exception("write rows to csv failed!" + e.getMessage());
        }
    }

    private void writeRowsToCSV(List<JSONObject> allRows, String csvFileName) throws Exception{
        if (allRows == null || allRows.size() == 0) {
            throw new Exception("rows is empty");
        }
        if (csvFileName == null || csvFileName.equals("")) {
            throw new Exception("filename is empty");
        }
        // 创建一个文件对象，若路径不存在，则创建；若存在，则覆盖
        File file = new File(csvFileName);
        FileWriter fileWriter = new FileWriter(file); // 创建一个输出流
        List<String> keys = new ArrayList<>();
        for (int i = 0; i < allRows.size(); i++) {
            Map<String, Object> row = allRows.get(i);
            if (i == 0) {
                // key一般固定，只对key进行一次处理
                keys.addAll(row.keySet());
                Collections.sort(keys);
                writeRowToCSV(keys, fileWriter);
            }
            List<Object> values = new ArrayList<>();
            for (String key : keys) {
                values.add(row.get(key));
            }
            writeRowToCSV(values, fileWriter);
        }
        fileWriter.close();
    }
    private void writeRowToCSV(List<?> vals, FileWriter fileWriter) throws IOException {
        for (int i = 0; i < vals.size(); i++) {
            fileWriter.append(vals.get(i).toString());
            if (i != vals.size() - 1) {
                fileWriter.append(",");
            }
        }
        fileWriter.append("\n");
    }

    private List<JSONObject> getAllRows(String url) {
        List<JSONObject> res = new ArrayList<>();
        Integer pageNum = 1;
        try {
            while (true) {
                DataResult curDataResult = getRows(url, pageNum);
                if (curDataResult.getRows() == null || curDataResult.getRows().size() == 0) {
                    break;
                }
                pageNum += 1;
                res.addAll(curDataResult.getRows());
            }
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
        return res;
    }

    /**
     * 获取每页的数据
     * @param url
     * @param pageNum
     * @return
     */

    private DataResult getRows(String url, Integer pageNum) {
        DataResult result = new DataResult();
        // 在获取每页数据中拼接pageNum
        url = url + "&pageNum=" + pageNum;
        JSONObject jsonData = HttpGet(client.getTemplate(), url);
        if (jsonData == null)
            return result;
        //把JSONRows解析为DataResult结构体
        try {
            result.setTotalNum(jsonData.getInteger(TOTAL_NUM));
            result.setPageSize(jsonData.getInteger(PAGE_SIZE));
            result.setPageNum(jsonData.getInteger(PAGE_NUM));
            result.setRows((List<JSONObject>) jsonData.get(ROWS));
        } catch (Exception e) {
            throw new RuntimeException("response data parsing failed: " + e.getMessage());
        }
        return result;
    }

    private String addPamaToUrl(String url, APIConfig apiConfig) throws Exception {
        String res = "";
        if (apiConfig.getParam() != null && apiConfig.getParam().size() > 0) {
            String queryString = mapToQueryString(apiConfig.getParam());
            if (url.contains("?")) {
                res = url + "&" + queryString;
            } else {
                res = url + "?" + queryString;
            }
        }
        return res;
    }

    /**
     * 接口数据同步为模型
     * @param request
     * @return
     * @param <T>
     * @throws Exception
     */
    public <T> List<T> syncToModel(SyncToModelRequest request) throws Exception {
        APIConfig apiConfig = request.getApiConfig();
        Class Model = request.getModel();
        String url = basicOperation(apiConfig);
        List<JSONObject> allRows = getAllRows(url);

        if (allRows == null) {
            throw new Exception("get all rows failed!");
        }
        Gson gson = new Gson();
        // 运用反射机制动态获取泛型类型
        try {
            ObjectMapper objectMapper = new ObjectMapper();
            objectMapper.registerModule(new JavaTimeModule());
            CollectionType javaType = objectMapper.getTypeFactory().constructCollectionType(List.class, Model);
            List<T> modelDataList = objectMapper.readValue(objectMapper.writeValueAsString(allRows), javaType);
            return modelDataList;
        } catch (Exception e) {
            return null;
        }
    }

    private String mapToQueryString(Map<String, Object> param) throws Exception {
        StringBuilder queryString = new StringBuilder();
        for (Map.Entry<String, Object> entry : param.entrySet()) {
            String key = entry.getKey();
            Object value = entry.getValue();
            if (value != null) {
                if (queryString.length() > 0) {
                    queryString.append("&");
                }
                try {
                    queryString.append(key);
                    queryString.append("=");
                    queryString.append(value.toString());
                } catch (Exception e) {
                    throw new Exception("map transfer to query string failed: " + e.getMessage());
                }
            }
        }
        return queryString.toString();
    }

    /**
     * 接口数据同步到数据库
     * @param request
     * @return 成功插入条数
     * @param <T>
     * @throws Exception
     */

    public <T> Integer syncToDB(SyncToDBRequest request) throws Exception {
        Session session = request.getSession();
        APIConfig apiConfig = request.getApiConfig();
        String url = basicOperation(apiConfig);
        // 根据Model匹配表，如不存在，则创建；反之检查两者结构是否匹配
        // 获取当前事务
        Transaction tx = session.getTransaction();
        Integer totalSaved = 0;
        try {
            if (tx == null || !tx.isActive()) {
                tx = session.beginTransaction();
            }
            // 将上述列表中的对象插入数据库中
            for (int i = 1; ; i++) {
                DataResult dataresult = getRows(url, i);
                if (dataresult == null) break;
                List<JSONObject> rowsPerPage = dataresult.getRows();
                if (rowsPerPage == null || rowsPerPage.size() == 0) break;
                // 转化为model
                ObjectMapper objectMapper = new ObjectMapper();
                objectMapper.registerModule(new JavaTimeModule());
                CollectionType javaType = objectMapper.getTypeFactory().constructCollectionType(List.class, request.getModel());
                List<T> modelsPerPage = objectMapper.readValue(objectMapper.writeValueAsString(rowsPerPage), javaType);
                Integer savedPerPage = batchSyncToDB(session, apiConfig.getBatchSize(), modelsPerPage);
                totalSaved += savedPerPage;
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
     * @param session
     * @param batchSize
     * @param modelList
     * @return
     */

    private Integer batchSyncToDB (Session session, Integer batchSize, List<?> modelList) throws Exception {
        int successfulSave = 0;
        try {
            for (int i = 0; i < modelList.size(); i++) {
                // 针对主键进行查询，若存在，则更新；反之插入
                session.saveOrUpdate(modelList.get(i));
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
     * @param client
     * @return 失效：返回负数；未失效，返回正数，剩余时间
     */

    private Boolean isRenewToken(OAuth2Client client) {
        OAuth2AccessToken token = client.getTemplate().getAccessToken();
        if (token == null)  return false;
        Date expirationDate = token.getExpiration();
        long currenTs = System.currentTimeMillis();
        long expirationTs = expirationDate.getTime();
        long remainTs = expirationTs - currenTs;
        if (remainTs < 0 || (remainTs > 0 && remainTs < NEAR_EXPIRE_TIME)) {
            return true;
        } else {
            return false;
        }
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
            Date newExpirationDate = new Date(accessToken.getExpiration().getTime() + DEFAULT_TOKEN_DURATION);
            DefaultOAuth2AccessToken newToken = new DefaultOAuth2AccessToken(accessToken);
            newToken.setExpiration(newExpirationDate);
            template.getOAuth2ClientContext().setAccessToken(newToken);
        }
    }
}
