package com.ecnu.example.entity;

import lombok.Data;

import javax.persistence.Id;
import java.util.Date;
@Data
public class Fake {
    @Id
    public Integer id;
    public String colString1;
    public String colString2;
    public String colString3;
    public String colString4;
    public String colInt1;
    public String colInt2;
    public String colInt3;
    public String colInt4;
    public Float colFloat1;
    public Float colFloat2;
    public Float colFloat3;
    public Float colFloat4;
    public Date colSqlTime1;
    public Date colSqlTime2;
    public Date colSqlTime3;
    public Date colSqlTime4;

    public Fake() {
    }

    public Fake(Integer id, String colString1, String colString2, String colString3, String colString4, String colInt1, String colInt2, String colInt3, String colInt4, Float colFloat1, Float colFloat2, Float colFloat3, Float colFloat4, Date colSqlTime1, Date colSqlTime2, Date colSqlTime3, Date colSqlTime4) {
        this.id = id;
        this.colString1 = colString1;
        this.colString2 = colString2;
        this.colString3 = colString3;
        this.colString4 = colString4;
        this.colInt1 = colInt1;
        this.colInt2 = colInt2;
        this.colInt3 = colInt3;
        this.colInt4 = colInt4;
        this.colFloat1 = colFloat1;
        this.colFloat2 = colFloat2;
        this.colFloat3 = colFloat3;
        this.colFloat4 = colFloat4;
        this.colSqlTime1 = colSqlTime1;
        this.colSqlTime2 = colSqlTime2;
        this.colSqlTime3 = colSqlTime3;
        this.colSqlTime4 = colSqlTime4;
    }

}
