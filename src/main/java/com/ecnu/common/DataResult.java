package com.ecnu.common;

import com.alibaba.fastjson.JSONObject;
import com.google.gson.annotations.SerializedName;
import lombok.Data;

import java.util.List;

@Data
public class DataResult {
    @SerializedName("totalNum")
    private int totalNum;
    @SerializedName("pageSize")
    private int pageSize;
    @SerializedName("pageNum")
    private int pageNum;
    @SerializedName("rows")
    private List<JSONObject> rows;
}
