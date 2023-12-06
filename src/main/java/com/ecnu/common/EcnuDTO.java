package com.ecnu.common;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * @author HQIT shu
 * @date 2021/9/22
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
public class EcnuDTO<T> {
    private int errCode;
    private String errMsg;
    private String requestId;
    private T data;
}
