package com.agenttrust.control;

import com.fasterxml.jackson.core.StreamReadConstraints;
import org.springframework.boot.autoconfigure.jackson.Jackson2ObjectMapperBuilderCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/** Bounded parser constraints apply to inbound bodies and every authority response. */
@Configuration
public class JacksonSecurityConfiguration {
    @Bean
    Jackson2ObjectMapperBuilderCustomizer boundedJsonParser() {
        return builder -> builder.postConfigurer(mapper -> mapper.getFactory()
            .setStreamReadConstraints(StreamReadConstraints.builder()
                .maxNestingDepth(64)
                .maxNumberLength(128)
                .maxStringLength(262_144)
                .build()));
    }
}
