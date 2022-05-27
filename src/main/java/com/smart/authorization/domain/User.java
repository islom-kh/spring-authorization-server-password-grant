package com.smart.authorization.domain;

import com.smart.authorization.domain.value.Role;
import com.smart.authorization.domain.value.UserStatus;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.*;
import java.io.Serializable;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

@Getter
@Setter
@Entity
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "users", uniqueConstraints = {
        @UniqueConstraint(name = "uk_user_username", columnNames = {"username"}),
        @UniqueConstraint(name = "uk_user_email", columnNames = {"email"}),
        @UniqueConstraint(name = "uk_user_phone", columnNames = {"phone"})
})
public class User implements Serializable {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "first_name")
    private String firstName;

    @Column(name = "last_name")
    private String lastName;

    @Column(name = "username", nullable = false)
    private String username;

    @Column(name = "email")
    private String email;

    @Column(name = "phone")
    private String phone;

    @Column(name = "password")
    private String password;

    @Convert(converter = UserStatus.Converter.class)
    @Column(name = "status")
    private UserStatus status = UserStatus.ACTIVE;

    @Column(name = "timezone")
    private String timezone;

    @Column(name = "bio", columnDefinition = "TEXT")
    private String bio;


    @ElementCollection(targetClass = Role.class, fetch = FetchType.EAGER)
    @CollectionTable(
            name = "user_role",
            joinColumns = @JoinColumn(name = "user_id"),
            foreignKey = @ForeignKey(name = "fk_user_role_id")
    )
    @Column(name = "role", nullable = false)
    @Convert(converter = Role.Converter.class)
    private Set<Role> roles = new HashSet<>();

    public User(Long id, String firstName, String username, String password, Set<Role> roles) {
        this.id = id;
        this.firstName = firstName;
        this.username = username;
        this.password = password;
        this.roles = roles;
    }

    public String[] getStringRoles() {
        String[] stringRoles = new String[0];
        return roles.parallelStream().map(Role::getId).collect(Collectors.toList()).toArray(stringRoles);
    }


}
