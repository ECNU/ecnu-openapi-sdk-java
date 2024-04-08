package com.ecnu.common;

import com.ecnu.util.Constants;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;

/**
 * @author lc
 * @create 2023/10/13-16:28
 * @description
 */

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class OAuth2Config {
    private String clientId; // 必须
    private String clientSecret; // 必须
    @Builder.Default
    private String baseUrl = Constants.DEFAULT_BASE_URL;
    @Builder.Default
    private List<String> scopes = new ArrayList<String>() {{
        add(Constants.DEFAULT_SCOPE);
    }};
    @Builder.Default
    private Integer timeout = Constants.DEFAULT_TIMEOUT;
    @Builder.Default
    private Boolean debug = false;

    private String redirectUrl;
    @Builder.Default
    private String userInfoUrl = Constants.DEFAULT_USER_INFO_URL;
    @Builder.Default
    private String accessTokenUrl = Constants.DEFAULT_ACCESS_TOKEN_URL;
    @Builder.Default
    private String userAuthUrl = Constants.DEFAULT_USER_AUTH_URL;
    @Builder.Default
    private Integer expirationTime = Constants.EXPIRATION_TIME;

}
