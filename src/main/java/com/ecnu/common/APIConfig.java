package com.ecnu.common;

import com.google.gson.annotations.SerializedName;
import com.ecnu.constants.Constants;
import lombok.Data;

import java.util.Map;

/**
 * @author lc
 * @create 2023/10/15-09:46
 * @description
 */

@Data
public class APIConfig {
    /**
     * api路径，必填
     */
//    @SerializedName("api_path")
    private String APIPath;
    /**
     * 翻页大小，最大10000，默认2000
     */
//    @SerializedName("page_size")
    private Integer pageSize; //
    /**
     * 批量写入数据的批次大小，默认100
     */
//    @SerializedName("data_batch")
    private Integer batchSize;
    /**
     * 用于批量同步，数据库对应的时间戳字段，默认updated_at
     */
    private String updatedAtField;
    private Map<String, Object> param;

    public APIConfig() {

    }

    public APIConfig(String APIPath, Integer pageSize, Integer batchSize, String updatedAtField, Map<String, Object> param) {
        this.APIPath = APIPath;
        this.pageSize = pageSize;
        this.batchSize = batchSize;
        this.updatedAtField = updatedAtField;
        this.param = param;
    }

    public void setDefault() {
        if (this.getPageSize() == null || this.getPageSize() == 0) {
            this.setPageSize(2000);
        } else if (this.getPageSize() > Constants.MAX_PAGE_SIZE) {
            this.setPageSize(Constants.MAX_PAGE_SIZE);
        }
        if (this.getBatchSize() == null || this.getBatchSize() == 0) {
            this.setBatchSize(100);
        }
        if (this.getUpdatedAtField() == null || this.getUpdatedAtField().equals("")) {
            this.setUpdatedAtField("updated_at");
        }
    }

}
