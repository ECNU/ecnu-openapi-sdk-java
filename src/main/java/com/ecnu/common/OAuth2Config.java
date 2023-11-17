package com.ecnu.common;

import com.ecnu.constants.Constants;
import com.google.gson.annotations.SerializedName;
import lombok.Data;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * @author lc
 * @create 2023/10/13-16:28
 * @description
 */

@Data
public class OAuth2Config implements Serializable {
    @SerializedName("client_id")
    private String clientId; // 必须
    @SerializedName("client_secrete")
    private String clientSecret; // 必须
    @SerializedName("base_url")
    private String baseUrl; // 默认 https://api.ecnu.edu.cn
    @SerializedName("scopes")
    private List<String> scopes; //默认 ["ECNU-Basic"]
    @SerializedName("timeout")
    private Integer timeout;//默认10秒
    @SerializedName("debug")
    private Boolean debug;//默认 false, 如果开启 debug，会打印出请求和响应的详细信息，对于数据同步类接口而言可能会非常大

    public OAuth2Config() {
    }

    public OAuth2Config(String clientId, String clientSecret) {
        this.clientId = clientId;
        this.clientSecret = clientSecret;
    }
}
