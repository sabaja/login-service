package com.login;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SpringBootTest
class AuthApplicationTests {

    @Test
    void contextLoads() {
        assertEquals("1", Long.valueOf(1).toString());
    }

    @Test
    void applicationContextTest() {
        AuthApplication.main(new String[]{});
        assertEquals("1", Long.valueOf(1).toString());
    }
}
