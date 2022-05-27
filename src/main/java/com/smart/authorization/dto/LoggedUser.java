package com.smart.authorization.dto;

import com.smart.authorization.domain.User;
import com.smart.authorization.domain.value.Role;
import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.authority.AuthorityUtils;

import java.util.Set;
import java.util.stream.Collectors;

/**
 * Author: rustam.akhmedov@gmail.com
 * Date: 3/1/18
 * Time: 12:12
 */

@Getter
@Setter
public class LoggedUser extends org.springframework.security.core.userdetails.User {

    private  User user;
    private Long id;
    private Set<Role> roles;
    private String firstName;
    private String lastName;
    private String timezone;

    public LoggedUser(User user) {
        super(user.getUsername(), user.getPassword(), true, true, true, true, AuthorityUtils.createAuthorityList(user.getStringRoles()));
        this.user = user;
        this.id = user.getId();
        this.firstName = user.getFirstName();
        this.lastName = user.getLastName();
        this.timezone = user.getTimezone();
        this.roles = getAuthorities().parallelStream().map(r -> Role.fromString(r.getAuthority())).collect(Collectors.toSet());
    }

    public Long getId() {
        return id;
    }
}
