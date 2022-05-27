package com.smart.authorization.domain.value;

import javax.persistence.AttributeConverter;

/**
 * Author: rustam.akhmedov@gmail.com
 * Date: 2/22/18
 * Time: 14:25
 */
public enum UserStatus {
    INACTIVE(0), ACTIVE(1), DELETED(2);

// ------------------------------ FIELDS ------------------------------

    private final int id;

// -------------------------- STATIC METHODS --------------------------

    public static UserStatus create(int value) {
        for (UserStatus v : values()) {
            if (value == (v.getId())) {
                return v;
            }
        }
        return null;
    }

    public static UserStatus fromInt(int value) {
        for (UserStatus v : values()) {
            if (value == v.getId())
                return v;
        }
        return null;
    }

// --------------------------- CONSTRUCTORS ---------------------------

    UserStatus(int id) {
        this.id = id;
    }

// --------------------- GETTER / SETTER METHODS ---------------------

    public int getId() {
        return id;
    }

// -------------------------- INNER CLASSES --------------------------

    @javax.persistence.Converter(autoApply = true)
    public static class Converter implements AttributeConverter<UserStatus, Integer> {
        @Override
        public Integer convertToDatabaseColumn(UserStatus attribute) {
            return attribute.getId();
        }

        @Override
        public UserStatus convertToEntityAttribute(Integer dbData) {
            return create(dbData);
        }
    }
}
