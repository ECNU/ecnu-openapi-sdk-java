package com.ecnu.util;

public class Constants {
    /**
     * OAuth2Config相关
     */
    public static final String DEFAULT_SCOPE = "ECNU-Basic";
    public static final String DEFAULT_BASE_URL = "https://api.ecnu.edu.cn";
    public static final Integer DEFAULT_TIMEOUT = 10;
    public static final String Invalid_Token_ERROR = "A401OT";

    public static final String DEFAULT_USER_INFO_URL = "https://api.ecnu.edu.cn/oauth2/userinfo";
    public static final String DEFAULT_ACCESS_TOKEN_URL = "https://api.ecnu.edu.cn/oauth2/token";
    public static final String DEFAULT_USER_AUTH_URL = "https://api.ecnu.edu.cn/oauth2/authorize";
    public static final Integer EXPIRATION_TIME = 10;



    /**
     * api相关
     */
    public static final Integer MAX_PAGE_SIZE = 10000;
    /**
     * token相关
     */
    public static final long NEAR_EXPIRE_TIME = 10 * 60 * 1000;
    public static final long DEFAULT_TOKEN_DURATION = 2 * 60 * 60 * 1000;
}
