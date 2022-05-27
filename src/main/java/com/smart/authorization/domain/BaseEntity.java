package com.smart.authorization.domain;

import lombok.Getter;
import lombok.Setter;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import javax.persistence.EntityListeners;
import java.time.Instant;

@Getter
@Setter
@EntityListeners(AuditingEntityListener.class)
public class BaseEntity {

    @CreatedDate
    private Instant createdDate;

    @LastModifiedDate
    private Instant updatedDate;
}
