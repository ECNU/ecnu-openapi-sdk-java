package com.ecnu.example.entity;

import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.Data;

import javax.persistence.Id;
import java.time.LocalDateTime;

@Data
public class FakeWithTS {
    @Id
    private int id;
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd HH:mm:ss")
    private LocalDateTime created_at;
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd HH:mm:ss")
    private LocalDateTime updated_at;
    private int deleted_mark;
    private String userId;
    private String name;

    public FakeWithTS() {
    }

    public FakeWithTS(int id, LocalDateTime created_at, LocalDateTime updated_at, int deleted_mark, String userId, String name) {
        this.id = id;
        this.created_at = created_at;
        this.updated_at = updated_at;
        this.deleted_mark = deleted_mark;
        this.userId = userId;
        this.name = name;
    }
}
