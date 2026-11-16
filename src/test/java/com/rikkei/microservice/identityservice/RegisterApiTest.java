package com.rikkei.microservice.identityservice;

import com.rikkei.microservice.identityservice.dto.AuthResponse;
import com.rikkei.microservice.identityservice.dto.LoginRequest;
import com.rikkei.microservice.identityservice.dto.RegisterRequest;
import com.rikkei.microservice.identityservice.dto.UserResponse;
import com.rikkei.microservice.identityservice.entity.RefreshToken;
import com.rikkei.microservice.identityservice.entity.User;
import com.rikkei.microservice.identityservice.repository.RefreshTokenRepository;
import com.rikkei.microservice.identityservice.repository.UserRepository;
import com.rikkei.microservice.identityservice.security.JwtUtils;
import com.rikkei.microservice.identityservice.service.AuthService;
import com.rikkei.microservice.identityservice.service.RefreshTokenService;
import io.jsonwebtoken.Claims;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Instant;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
class IdentityServiceTests {

    @Autowired
    private AuthService authService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private RefreshTokenService refreshTokenService;

    @BeforeEach
    void setUp() {
        refreshTokenRepository.deleteAll();
        userRepository.deleteAll();
    }

    @Test
    @DisplayName("Bài 1: Đăng ký thành công, password được băm BCrypt")
    void testRegister_Success() {
        RegisterRequest request = RegisterRequest.builder()
                .username("john_doe")
                .password("Password123@")
                .role("ADMIN")
                .build();

        UserResponse response = authService.register(request);

        assertNotNull(response.getId());
        assertEquals("john_doe", response.getUsername());
        assertEquals("ADMIN", response.getRole());

        User savedUser = userRepository.findByUsername("john_doe").orElse(null);
        assertNotNull(savedUser);
        assertTrue(passwordEncoder.matches("Password123@", savedUser.getPassword()));
    }

    @Test
    @DisplayName("Bài 2: Sinh JWT Access Token với subject là username và custom claim role")
    void testGenerateToken_Claims() {
        User user = User.builder()
                .id("test-id-123")
                .username("test_user")
                .password("hashed_password")
                .role("ROLE_MANAGER")
                .build();

        String token = jwtUtils.generateAccessToken(user);
        assertNotNull(token);
        assertFalse(token.isEmpty());

        Claims claims = jwtUtils.extractAllClaims(token);
        assertEquals("test_user", claims.getSubject(), "Subject (sub) claim phải là username");
        assertEquals("ROLE_MANAGER", claims.get("role"), "Role claim phải khớp role của user");
        assertNotNull(claims.getExpiration(), "Token phải có thời gian hết hạn");
    }

    @Test
    @DisplayName("Bài 3 & Bài 5: Đăng nhập thành công -> Trả về cả Access Token và Refresh Token")
    void testLogin_Success_ReturnsBothTokens() {
        authService.register(RegisterRequest.builder()
                .username("alice")
                .password("alicePassword123")
                .role("USER")
                .build());

        LoginRequest loginRequest = LoginRequest.builder()
                .username("alice")
                .password("alicePassword123")
                .build();

        AuthResponse authResponse = authService.login(loginRequest);
        assertNotNull(authResponse);
        assertNotNull(authResponse.getAccessToken());
        assertNotNull(authResponse.getRefreshToken());
        assertEquals("Bearer", authResponse.getTokenType());

        // Kiểm tra Access Token
        Claims claims = jwtUtils.extractAllClaims(authResponse.getAccessToken());
        assertEquals("alice", claims.getSubject());
        assertEquals("USER", claims.get("role"));

        // Kiểm tra Refresh Token được lưu trong DB
        RefreshToken storedRefreshToken = refreshTokenRepository.findByToken(authResponse.getRefreshToken()).orElse(null);
        assertNotNull(storedRefreshToken);
        assertEquals("alice", storedRefreshToken.getUser().getUsername());
        assertTrue(storedRefreshToken.getExpiryDate().isAfter(Instant.now()));

        // Kiểm tra verifyExpiration hoạt động
        RefreshToken verified = refreshTokenService.verifyExpiration(storedRefreshToken);
        assertNotNull(verified);
    }

    @Test
    @DisplayName("RefreshTokenService: verifyExpiration ném ngoại lệ khi token hết hạn")
    void testVerifyExpiration_ExpiredToken() {
        User user = userRepository.save(User.builder()
                .username("expired_user")
                .password("123456")
                .role("USER")
                .build());

        RefreshToken expiredToken = refreshTokenRepository.save(RefreshToken.builder()
                .user(user)
                .token(UUID.randomUUID().toString())
                .expiryDate(Instant.now().minusSeconds(100))
                .build());

        assertThrows(RuntimeException.class, () -> {
            refreshTokenService.verifyExpiration(expiredToken);
        });
    }

    @Test
    @DisplayName("Bài 3: Đăng nhập thất bại do sai mật khẩu -> Ném BadCredentialsException")
    void testLogin_Failed_BadCredentials() {
        authService.register(RegisterRequest.builder()
                .username("alice")
                .password("alicePassword123")
                .role("USER")
                .build());

        LoginRequest wrongPasswordRequest = LoginRequest.builder()
                .username("alice")
                .password("wrongPassword")
                .build();

        BadCredentialsException ex = assertThrows(BadCredentialsException.class, () -> {
            authService.login(wrongPasswordRequest);
        });
        assertEquals("Bad credentials", ex.getMessage());
    }
}
