package com.example.demo.payload.response;

import com.example.demo.model.User;
import lombok.Data;

import java.time.ZonedDateTime;
import java.util.UUID;

@Data
public class UserResponse {

    private final String nickname;
    private final String email;
    private final ZonedDateTime createdAt;
    private final UUID uuid;
    private final RoleResponse role;

    public UserResponse(User user) {
        this.nickname = user.getNickname();
        this.email = user.getEmail();
        this.createdAt = user.getCreatedAt();
        this.uuid = user.getUuid();
        this.role = new RoleResponse(user.getRole());
    }

}
