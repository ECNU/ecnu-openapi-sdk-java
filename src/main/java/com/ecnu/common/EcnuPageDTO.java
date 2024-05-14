package com.ecnu.common;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * @author HQIT shu
 * @date 2021/9/22
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
public class EcnuPageDTO<T> {
    private int totalNum;
    private int pageSize;
    private int pageNum;
    private List<T> rows;
}
