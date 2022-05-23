package eu.gaiax.difs.aas.config;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import eu.gaiax.difs.aas.properties.ServerProperties;

@SpringBootTest(properties = {"server.port=9000", "server.schema=https"})
public class ServerPropertiesTest {

    @Autowired
    private ServerProperties serverProps;
    
    @Test
    public void testBaseUrl() throws Exception {
        assertEquals("https://auth-server:9000", serverProps.getBaseUrl());
    }
    
}
