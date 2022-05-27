package com.smart.authorization.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.context.annotation.Configuration;

@Data
@Configuration
@ConfigurationProperties("app")
public class AppProperties {
    @NestedConfigurationProperty
    private Oauth2Properties oauth2;

    private String smsServiceName;
}
