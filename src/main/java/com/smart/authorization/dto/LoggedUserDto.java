package com.smart.authorization.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;


@Getter
@Setter
@NoArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class LoggedUserDto {
    private Long id;
    private String firstName;
    private String lastName;
    private String email;
    private String timezone;
}
