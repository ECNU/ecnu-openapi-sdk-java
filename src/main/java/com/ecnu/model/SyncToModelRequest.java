package com.ecnu.model;

import com.ecnu.common.APIConfig;
import lombok.Data;

/**
 * @author lc
 * @create 2023/10/17-15:48
 * @description
 */

@Data
public class SyncToModelRequest {
    private APIConfig apiConfig;
    private Class model;

    public SyncToModelRequest() {
    }

    public SyncToModelRequest(APIConfig apiConfig, Class model) {
        this.apiConfig = apiConfig;
        this.model = model;
    }
}
