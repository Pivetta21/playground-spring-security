package com.example.demo.model;

import com.example.demo.security.model.RoleEnum;
import lombok.*;

import javax.persistence.*;
import java.util.HashSet;
import java.util.Set;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Entity
public class Role {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, unique = true, length = 30)
    private RoleEnum name;

    @OneToMany(mappedBy = "role")
    private Set<User> users = new HashSet<>();

    @ManyToMany
    @JoinTable(
            name = "role_permission",
            joinColumns = @JoinColumn(name = "fk_role", referencedColumnName = "id"),
            inverseJoinColumns = @JoinColumn(name = "fk_permission", referencedColumnName = "id")
    )
    private Set<Permission> permissions = new HashSet<>();

}
