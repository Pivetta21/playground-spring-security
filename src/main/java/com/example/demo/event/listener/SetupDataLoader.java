package com.example.demo.event.listener;

import com.example.demo.model.Permission;
import com.example.demo.model.RefreshToken;
import com.example.demo.model.Role;
import com.example.demo.model.User;
import com.example.demo.repository.PermissionRepository;
import com.example.demo.repository.RefreshTokenRepository;
import com.example.demo.repository.RoleRepository;
import com.example.demo.security.model.PermissionEnum;
import com.example.demo.security.model.RoleEnum;
import com.example.demo.security.util.JwtUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationListener;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.lang.NonNull;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import javax.transaction.Transactional;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

@Slf4j
@Component
public class SetupDataLoader implements ApplicationListener<ContextRefreshedEvent> {

    volatile boolean isAlreadySetup = false;

    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;
    private final PasswordEncoder passwordEncoder;
    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtUtil jwtUtil;

    public SetupDataLoader(
            RoleRepository roleRepository,
            PermissionRepository permissionRepository,
            PasswordEncoder passwordEncoder,
            RefreshTokenRepository refreshTokenRepository,
            JwtUtil jwtUtil
    ) {
        this.roleRepository = roleRepository;
        this.permissionRepository = permissionRepository;
        this.passwordEncoder = passwordEncoder;
        this.refreshTokenRepository = refreshTokenRepository;
        this.jwtUtil = jwtUtil;
    }

    @Override
    public void onApplicationEvent(@NonNull ContextRefreshedEvent event) {
        if (isAlreadySetup) return;
        log.info("Starting role and permission data loader");

        Map<PermissionEnum, Permission> permissions = new HashMap<>();
        for (PermissionEnum permission : PermissionEnum.values()) {
            permissions.put(permission, createPermissionIfNotFound(permission));
        }

        Map<RoleEnum, Role> roles = new HashMap<>();
        for (RoleEnum role : RoleEnum.values()) {
            Set<Permission> permissionsSet = role.getPermissions().stream().map(permissions::get).collect(Collectors.toSet());
            roles.put(role, createRoleIfNotFound(role, permissionsSet));
        }

        Role adminRole = roles.get(RoleEnum.ADMIN);
        createUser("admin", "admin@email.com", "123456", adminRole);

        Role staffRole = roles.get(RoleEnum.STAFF);
        createUser("staff", "staff@email.com", "teste001", staffRole);

        log.info("Finished role and permission data loader");
        isAlreadySetup = true;
    }

    @Transactional
    void createUser(String name, String email, String password, Role role) {
        var user = User.builder()
                .email(email)
                .password(passwordEncoder.encode(password))
                .createdAt(ZonedDateTime.now(ZoneId.of("Z")))
                .uuid(UUID.randomUUID())
                .nickname(name)
                .role(role)
                .build();

        String refreshToken = jwtUtil.createRefreshToken(user);

        RefreshToken rt = RefreshToken.builder().refreshToken(refreshToken).user(user).build();
        refreshTokenRepository.save(rt);
    }

    @Transactional
    Permission createPermissionIfNotFound(PermissionEnum permissionEnum) {
        return permissionRepository.findByName(permissionEnum).orElseGet(() -> {
            var permission = Permission.builder().name(permissionEnum).build();
            return permissionRepository.save(permission);
        });
    }

    @Transactional
    Role createRoleIfNotFound(RoleEnum roleEnum, Set<Permission> permissionsSet) {
        return roleRepository.findByName(roleEnum).orElseGet(() -> {
            var role = Role.builder().name(roleEnum).permissions(permissionsSet).build();
            return roleRepository.save(role);
        });
    }

}
