package com.ecnu.model;

import com.ecnu.common.APIConfig;
import lombok.Data;
import org.hibernate.Session;

/**
 * @author lc
 * @create 2023/10/17-16:32
 * @description
 */

@Data
public class SyncToDBRequest {
    private APIConfig apiConfig;
    private Class model;
    private Session session;

    public SyncToDBRequest() {
    }

    public SyncToDBRequest(APIConfig apiConfig, Class model, Session session) {
        this.apiConfig = apiConfig;
        this.model = model;
        this.session = session;
    }
}
