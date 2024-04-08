package com.ecnu.example;

import com.ecnu.OAuth2Client;
import com.ecnu.common.OAuth2Config;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

public class AuthCodeExample {

    public static void main(String[] args) throws IOException {
        OAuth2Config cf = OAuth2Config.builder()
                .clientId("client_id")
                .clientSecret("client_secret")
                .redirectUrl("http://localhost:8080/user")
                .debug(true)
                .build();
        // 获取单例OAuth2Client实例
        OAuth2Client client = OAuth2Client.getClient();
        // 使用配置初始化OAuth2Client
        client.initOAuth2AuthorizationCode(cf);
        // 创建HTTP服务器，监听本地的8080端口
        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);

        // 处理/login路径的请求
        server.createContext("/login", new HttpHandler() {
            @Override
            public void handle(HttpExchange exchange) throws IOException {
                String state = client.generateRandomState();
                String authorizationUrl = client.getAuthorizationEndpoint(state);
                // 重定向到授权URL
                exchange.getResponseHeaders().set("Location", authorizationUrl);
                exchange.sendResponseHeaders(302, -1);
                exchange.close();
            }
        });

        // 处理/user路径的请求
        server.createContext("/user", new HttpHandler() {
            @Override
            public void handle(HttpExchange exchange) throws IOException {
                URI requestUri = exchange.getRequestURI();
                Map<String, String> queryParams = queryToMap(requestUri.getQuery());

                String code = queryParams.get("code");
                String state = queryParams.get("state");
                // 校验code非空
                if (code == null || code.isEmpty()) {
                    sendResponse(exchange, "Code not found", 400);
                    return;
                }
                try {
                    String response = client.getInfo(code, state);
                    exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
                    exchange.sendResponseHeaders(200, response.getBytes(StandardCharsets.UTF_8).length);
                    OutputStream os = exchange.getResponseBody();
                    os.write(response.getBytes());
                    os.close();
                } catch (Exception e) {
                    // 日志记录异常或进行其他错误处理
                    System.err.println("Error processing request: " + e.getMessage());
                    // 发送服务器内部错误响应
                    sendResponse(exchange, "Internal Server Error", 500);
                }

            }
            private Map<String, String> queryToMap(String query) {
                Map<String, String> result = new HashMap<>();
                if (query == null) return result;
                for (String param : query.split("&")) {
                    String[] entry = param.split("=");
                    if (entry.length > 1) {
                        result.put(entry[0], entry[1]);
                    } else {
                        result.put(entry[0], "");
                    }
                }
                return result;
            }
            private void sendResponse(HttpExchange exchange, String response, int statusCode) throws IOException {
                exchange.getResponseHeaders().set("Content-Type", "text/html; charset=utf-8");
                exchange.sendResponseHeaders(statusCode, response.getBytes().length);
                OutputStream os = exchange.getResponseBody();
                os.write(response.getBytes());
                os.close();
            }

        });

        // 启动服务器
        server.start();
        System.out.println("Server started on port 8080");
    }
}