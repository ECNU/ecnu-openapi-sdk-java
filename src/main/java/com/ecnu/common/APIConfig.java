package com.ecnu.common;

import com.ecnu.util.Constants;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Map;

/**
 * @author lc
 * @create 2023/10/15-09:46
 * @description
 */

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ApiConfig {
    /**
     * api路径，必填
     */
    private String apiPath;
    /**
     * 翻页大小，最大10000，默认2000
     */
    @Builder.Default
    private Integer pageSize = 2000;
    /**
     * 批量写入数据的批次大小，默认100
     */
    @Builder.Default
    private Integer batchSize = 100;
    /**
     * 用于批量同步，数据库对应的时间戳字段，默认updated_at
     */
    @Builder.Default
    private String updatedAtField = "updated_at";

    private Map<String, Object> param;

    public void setDefault() {
        if (this.getPageSize() == 0) {
            this.setPageSize(2000);
        }
        if (this.getPageSize() > Constants.MAX_PAGE_SIZE) {
            this.setPageSize(Constants.MAX_PAGE_SIZE);
        }
        if (this.getBatchSize() == 0) {
            this.setBatchSize(100);
        }
    }
}
