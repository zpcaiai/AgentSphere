package com.agenttrust.control;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(ControlProperties.class)
public class EnterpriseControlApplication {
    public static void main(String[] args) {
        SpringApplication.run(EnterpriseControlApplication.class, args);
    }
}
