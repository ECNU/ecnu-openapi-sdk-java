package com.ecnu.model;

import com.alibaba.fastjson.JSONObject;
import lombok.Data;

import java.util.Map;

@Data
public class CallAPIRequest {

    private String url;
    private String method;
    private Map<String, String> header;
    private JSONObject body;

    public CallAPIRequest() {
    }

    public CallAPIRequest(String url, String method, Map<String, String> header, JSONObject body) {
        this.url = url;
        this.method = method;
        this.header = header;
        this.body = body;
    }
}

