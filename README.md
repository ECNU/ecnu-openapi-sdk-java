# Java-SDK

## 能力
- 授权模式（token 管理）
    - [x] client_credentials 模式
    - [ ] password 模式
    - [ ] authorization code 模式
- 接口调用
    - [x] GET
    - [ ] POST
    - [ ] PUT
    - [ ] DELETE
- 数据同步（接口必须支持翻页）
    - 全量同步
        - [x] 同步为 csv 格式
        - [x] 同步为 xlsx 格式
        - [x] 同步到数据库
        - [x] 同步到模型
    - 增量同步（接口必须支持ts增量参数）
        - [x] 同步为 csv 格式
        - [x] 同步为 xlsx 格式
        - [x] 同步到数据库
        - [x] 同步到模型

## 依赖
- jdk 1.8
- hibernate 5.6.11
- Spring Security OAuth2 2.5.2
- Gson 2.8.9
- opencsv 5.6
- easyexcel 2.2.6

## 相关资料
- [oauth2.0](https://oauth.net/2/)
- [hibernate](https://hibernate.org/)

## 支持的数据库
理论上只要 hibernate支持的数据库驱动都可以支持，以下是测试的情况

如果hibernate无法直接支持，可以先同步到模型，然后自行处理数据入库的逻辑。

| 数据库        | 驱动                                           | 测试情况 |
|------------|----------------------------------------------| --- |
| MySQL      | com.mysql.cj.jdbc.Driver                     | 测试通过 |
| SQLite     | null                                         | 测试通过 |
| PostgreSQL | org.postgresql.Driver                        | 测试通过 |
| SQL Server | com.microsoft.sqlserver.jdbc.SQLServerDriver | 测试通过 |
| Oracle     | oracle.jdbc.driver.OrableDriver              | 测试通过 |

## 示例

```java
<dependency>
    <groupId>io.github.ecnu</groupId>
    <artifactId>ecnu-openapi-sdk-java</artifactId>
    <version>2.0.0-RELEASE</version>
</dependency>
```

### authorization code

Todo

### client_credentials
#### 接口调用
初始化 SDK 后直接调用接口即可，sdk 会自动接管 token 的有效期和续约管理。

```java
        OAuth2Config cf = OAuth2Config.builder()
            .clientId(ecnuConfig.getClientId())
            .clientSecret(ecnuConfig.getClientSecret())
            .build();
        OAuth2Client client = OAuth2Client.getClient();
        client.initOAuth2ClientCredentials(cf);

        String url = "https://api.ecnu.edu.cn/api/v1/sync/fakewithts?ts=0&pageNum=1&pageSize=1";
        // -------test callApi----------
        List<JSONObject> response = client.callAPI(url, "GET", null, null);
```

更多用法详见以下示例代码，和示例代码中的相关注释

- [CallAPI](src/main/java/com/ecnu/example/CallAPIExample.java)
- [SyncToCSV](src/main/java/com/ecnu/example/SyncToCSVExample.java)
- [SyncToXLSX](src/main/java/com/ecnu/example/SyncToXLSXExample.java)
- [SyncToModel](src/main/java/com/ecnu/example/SyncToModelExample.java)
- [SyncToDB](src/main/java/com/ecnu/example/SyncToDBExample.java)


## 性能

性能与 ORM 的实现方式（特别是对 upsert 的实现方式），数据库的实现方式，以及网络环境有关，不一定适用于所有情况。

当同步到数据库时，SDK 会采用分批读取/写入的方式，以减少内存的占用。

当同步到模型时，则会将所有数据写入到一个数组中，可能会占用较大的内存。

以下是测试环境

### 同步程序运行环境
- i5 cpu
- 32G 内存
- windows10 X64
- WD 固态硬盘
- dotnet 4.8

### 测试接口信息
- /api/v1/sync/fake
- 使用 pageSize=2000 仅限同步
- 接口请求耗时约 0.1 - 0.2 秒
- 接口数据示例

```json
{
	"errCode": 0,
	"errMsg": "success",
	"requestId": "73a60094-c0f1-4daf-bc58-4626fbef7a2b",
	"data": {
		"pageSize": 2000,
		"pageNum": 1,
		"totalNum": 10000,
		"rows": [{
			"id": 1,
			"colString1": "Oxqmn5MWCt",
			"colString2": "mzavQncWeNlOlFgUW7HC",
			"colString3": "mvy6K1HU7rdCicPbvvA3rNZcDWPhvV",
			"colString4": "XGsK5NVQHOu4JrmHZ9ZL1iLf0UYpdIvNIzswULzb",
			"colInt1": 3931594532918648027,
			"colInt2": 337586114254574578,
			"colInt3": 2291922259603323213,
			"colInt4": 3000562485500051124,
			"colFloat1": 0.46541339000557547,
			"colFloat2": 0.6307996439929248,
			"colFloat3": 0.9278393850101392,
			"colFloat4": 0.7286866920659677,
			"colSqlTime1": "2023-10-20 22:02:07",
			"colSqlTime2": "2023-10-20 22:02:07",
			"colSqlTime3": "2023-10-20 22:02:07",
			"colSqlTime4": "2023-10-20 22:02:07"
		}]
	}
}
```

### 测试结果
- 数据库：本地sqlite
- pageSize = 2000
- batchSize = 100

| 数量级 | Model Time(s) | Model Mem(MB) | sqlite  Time(s) | sqlite  Mem(MB) |
| :----: | :-----------: | :-----------: | --------------- | --------------- |
|   1W   |     1.748     |      164      | 3.078           | 117             |
|  10W   |    13.129     |      426      | 20.144          | 167             |
|  100W  |    123.48     |     4791      | 156.255         | 168             |

