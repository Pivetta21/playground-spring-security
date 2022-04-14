package com.example.demo.payload.response;

import com.example.demo.model.Permission;
import com.example.demo.model.Role;
import com.example.demo.security.model.PermissionEnum;
import com.example.demo.security.model.RoleEnum;
import lombok.Data;

import java.util.List;

@Data
public class RoleResponse {

    private final RoleEnum name;
    private final List<PermissionEnum> permissions;

    public RoleResponse(Role role) {
        this.name = role.getName();
        this.permissions = role.getPermissions().stream().map(Permission::getName).toList();
    }

}
