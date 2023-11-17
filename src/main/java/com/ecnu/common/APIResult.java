package com.ecnu.common;
import com.alibaba.fastjson.JSONObject;
import com.google.gson.annotations.SerializedName;
import lombok.Data;

/**
 * @author lc
 * @create 2023/10/13-16:47
 * @description
 */

@Data
public class APIResult {
    /**
     * 错误码
     */
    @SerializedName("errCode")
    private Integer errCode;
    /**
     * 错误信息
     */
    @SerializedName("errMsg")
    private String errMsg;
    /**
     * 请求id
     */
    @SerializedName("requestId")
    private String requestId;
    /**
     * Data
     */
    @SerializedName("data")
    private JSONObject data;
}
