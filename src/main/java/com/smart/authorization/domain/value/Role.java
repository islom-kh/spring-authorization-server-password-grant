package com.smart.authorization.domain.value;

import javax.persistence.AttributeConverter;

public enum Role {
    ROOT("ROOT"),
    ADMIN("ADMIN"),
    USER("USER");

    private final String id;

    Role(String id) {
        this.id = id;
    }

    public static Role fromString(String value) {
        for (Role v : values()) {
            if (value.equalsIgnoreCase(v.getId()))
                return v;
        }
        return null;
    }

    public String getId() {
        return id;
    }

    @javax.persistence.Converter(autoApply = true)
    public static class Converter implements AttributeConverter<Role, String> {
        @Override
        public String convertToDatabaseColumn(Role attribute) {
            return attribute.getId();
        }

        @Override
        public Role convertToEntityAttribute(String dbData) {
            return fromString(dbData);
        }
    }
}
