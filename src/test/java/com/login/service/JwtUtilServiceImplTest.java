package com.login.service;

import com.login.exception.JwtTokenMalformedException;
import com.login.exception.JwtTokenMissingException;
import com.login.exception.UserException;
import io.jsonwebtoken.Jwts;
import org.apache.commons.codec.digest.HmacUtils;
import org.apache.logging.log4j.util.Strings;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

import static com.login.service.JwtUtilServiceImpl.*;
import static org.junit.jupiter.api.Assertions.*;


class JwtUtilServiceImplTest {

    private final String TOKEN = "eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2NzIzNDU0ODcsImlhdCI6MTY3MjMwOTQ4N30.M9YX0U4AEM2ZmiDnJ3jTUJYfRtNzXdi8KFM9qpw0k10";
    private final String UNSUPPORTED_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6ImludmFsaWRUeXBlIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.xJYP_PkUlAOXY6uNZNA8Q9uMMej8yxehRkEcZVfDUDE";
    private String invalidToken;
    private JwtUtilServiceImpl jwtUtilService;
    private UserDetails user;
    private String jwtToken;


    @Mock
    private Jwts jwts;


    @BeforeEach
    public void setUp() {
        this.jwtUtilService = new JwtUtilServiceImpl();
        this.user = createUserDetails();
        Authentication authentication = createAuthentication(user);
        this.jwtToken = jwtUtilService.generateToken(authentication);
        this.invalidToken = createInvalidToken();
    }

    @Test
    @DisplayName("Exception - getUsername")
    void throwException_whenGetUsernameWithExpiredToken() {
        Exception exception = assertThrows(UserException.class, () -> jwtUtilService.getUsername(TOKEN));
        final String exceptionMessage = "JWT expired";
        final String actualMessage = exception.getMessage();
        assertTrue(actualMessage.contains(exceptionMessage));
    }

    @Test
    @DisplayName("getUsername")
    void shouldGetUsername() {
        //given
        //when
        final String userName = jwtUtilService.getUsername(jwtToken);

        //then
        assertNotNull(userName);
        assertEquals(user.getUsername(), userName);
    }

    @Test
    @DisplayName("generateToken")
    void shouldGenerateToken() {
        //given
        //when
        final String jwtToken = jwtUtilService.generateToken(user);

        //then
        assertNotNull(jwtToken);
    }

    @Test
    @DisplayName("expirationDate")
    void shouldExtractExpirationDate() {
        //given
        //when
        final LocalDateTime expirationDate = jwtUtilService.extractExpirationDate(jwtToken);
        assertNotNull(expirationDate);
        assertTrue(LocalDateTime.now().isBefore(expirationDate));
    }

    @Test
    @DisplayName("validateToken")
    void shouldValidateToken() {
        Exception exception1 = assertThrows(JwtTokenMalformedException.class, () -> jwtUtilService.validateToken(TOKEN, user));
        assertTrue(exception1.getMessage().contains(EXPIRED_JWT_TOKEN_ERROR_MESSAGE));

        Exception exception2 = assertThrows(JwtTokenMalformedException.class, () -> jwtUtilService.validateToken("WrongToken", user));
        assertTrue(exception2.getMessage().contains(INVALID_JWT_TOKEN_ERROR_MESSAGE));

        Exception exception3 = assertThrows(JwtTokenMalformedException.class, () -> jwtUtilService.validateToken(invalidToken, user));
        assertTrue(exception3.getMessage().contains(INVALID_JWT_TOKEN_ERROR_MESSAGE));

        Exception exception4 = assertThrows(JwtTokenMissingException.class, () -> jwtUtilService.validateToken(Strings.EMPTY, user));
        assertTrue(exception4.getMessage().contains(JWT_CLAIMS_STRING_IS_EMPTY_ERROR_MESSAGE));

        Exception exception5 = assertThrows(UserException.class, () -> jwtUtilService.validateToken(jwtToken, null));
        assertTrue(exception5.getMessage().contains(USER_IS_NULL_ERROR_MESSAGE));

//        Exception exception6 = assertThrows(JwtTokenMalformedException.class, () -> jwtUtilService.validateToken(UNSUPPORTED_TOKEN, user));
//        assertTrue(exception6.getMessage().contains(UNSUPPORTED_JWT_TOKEN_ERROR_MESSAGE));


        final Boolean isValidate1 = jwtUtilService.validateToken(jwtToken, user);
        assertTrue(isValidate1);

        final Boolean isValidate2 = jwtUtilService.validateToken(jwtToken, new User("TOM", "NoPassword", List.of(new SimpleGrantedAuthority("USER_ROLE"))));
        assertFalse(isValidate2);


    }

    private UserDetails createUserDetails() {
        return new User("USER", "password", List.of(new SimpleGrantedAuthority("USER_ROLE")));
    }

    private Authentication createAuthentication(UserDetails user) {
        return new TestingAuthenticationToken(user.getUsername(), user.getPassword(), new ArrayList<GrantedAuthority>(user.getAuthorities()));
    }

    private String createInvalidToken() {
        String hmacSHA256Algorithm = "HmacSHA256";
        String data = "baeldung";
        String key = "123456";
        return new HmacUtils(hmacSHA256Algorithm, key).hmacHex(data);
    }
}