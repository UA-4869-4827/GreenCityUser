package greencity.security.service;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import greencity.TestConst;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.refEq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.initMocks;

import greencity.ModelUtils;
import greencity.constant.ErrorMessage;
import greencity.dto.ownsecurity.OwnSecurityVO;
import greencity.dto.user.UserAdminRegistrationDto;
import greencity.dto.user.UserManagementDto;
import greencity.dto.user.UserVO;
import greencity.dto.verifyemail.VerifyEmailVO;
import greencity.entity.Language;
import greencity.entity.User;
import greencity.entity.VerifyEmail;
import greencity.enums.Role;
import greencity.enums.UserStatus;
import greencity.exception.exceptions.BadRefreshTokenException;
import greencity.exception.exceptions.BadUserStatusException;
import greencity.exception.exceptions.EmailNotVerified;
import greencity.exception.exceptions.PasswordsDoNotMatchesException;
import greencity.exception.exceptions.UserAlreadyHasPasswordException;
import greencity.exception.exceptions.UserAlreadyRegisteredException;
import greencity.exception.exceptions.UserBlockedException;
import greencity.exception.exceptions.UserDeactivatedException;
import greencity.exception.exceptions.WrongEmailException;
import greencity.exception.exceptions.WrongPasswordException;
import greencity.repository.UserRepo;
import greencity.security.dto.SuccessSignInDto;
import greencity.security.dto.ownsecurity.EmployeeSignUpDto;
import greencity.security.dto.ownsecurity.OwnSignInDto;
import greencity.security.dto.ownsecurity.OwnSignUpDto;
import greencity.security.dto.ownsecurity.SetPasswordDto;
import greencity.security.dto.ownsecurity.UpdatePasswordDto;
import greencity.security.jwt.JwtTool;
import greencity.security.repository.OwnSecurityRepo;
import greencity.security.repository.RestorePasswordEmailRepo;
import greencity.service.EmailService;
import greencity.service.UserService;
import io.jsonwebtoken.ExpiredJwtException;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;

import java.time.LocalDateTime;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.modelmapper.ModelMapper;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import java.io.IOException;
import java.security.GeneralSecurityException;
import greencity.exception.exceptions.BadRequestException;
import static org.mockito.Mockito.never;
import greencity.constant.AppConstant;
import greencity.security.dto.SuccessSignInDto;
import org.mockito.ArgumentCaptor;

import static org.mockito.ArgumentCaptor.forClass;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class OwnSecurityServiceImplTest {

    @Mock
    OwnSecurityRepo ownSecurityRepo;

    @Mock
    UserService userService;

    @Mock
    PasswordEncoder passwordEncoder;

    @Mock
    JwtTool jwtTool;

    @Mock
    RestorePasswordEmailRepo restorePasswordEmailRepo;

    @Mock
    ModelMapper modelMapper;

    @Mock
    UserRepo userRepo;

    @Mock
    EmailService emailService;

    @Mock
    GoogleIdTokenVerifier googleIdTokenVerifier;

    @Mock
    private GoogleIdToken googleIdToken;

    @Mock
    private GoogleIdToken.Payload googlePayload;

    private OwnSecurityService ownSecurityService;

    private UserVO verifiedUser;
    private OwnSignInDto ownSignInDto;
    private UserVO notVerifiedUser;
    private UpdatePasswordDto updatePasswordDto;
    private UserManagementDto userManagementDto;

    private void mockVerifiedGoogleToken(String email, Object name)
            throws GeneralSecurityException, IOException {
        when(googleIdTokenVerifier.verify("valid-token")).thenReturn(googleIdToken);
        when(googleIdToken.getPayload()).thenReturn(googlePayload);
        when(googlePayload.getEmail()).thenReturn(email);
        when(googlePayload.getEmailVerified()).thenReturn(true);
        when(googlePayload.get("name")).thenReturn(name);
    }

    @BeforeEach
    public void init() {
        initMocks(this);
        ownSecurityService = new OwnSecurityServiceImpl(ownSecurityRepo, userService, passwordEncoder,
            jwtTool, 1, restorePasswordEmailRepo, modelMapper,
            userRepo, emailService, googleIdTokenVerifier);

        verifiedUser = UserVO.builder()
            .email("test@gmail.com")
            .id(1L)
            .userStatus(UserStatus.ACTIVATED)
            .ownSecurity(OwnSecurityVO.builder().password("password").build())
            .role(Role.ROLE_USER)
            .build();
        ownSignInDto = OwnSignInDto.builder()
            .email("test@gmail.com")
            .password("password")
            .build();
        notVerifiedUser = UserVO.builder()
            .email("test@gmail.com")
            .id(1L)
            .userStatus(UserStatus.ACTIVATED)
            .verifyEmail(new VerifyEmailVO())
            .ownSecurity(OwnSecurityVO.builder().password("password").build())
            .role(Role.ROLE_USER)
            .build();
        updatePasswordDto = UpdatePasswordDto.builder()
            .password("newPassword")
            .confirmPassword("newPassword")
            .build();
        userManagementDto = UserManagementDto.builder()
            .name(TestConst.NAME)
            .email(TestConst.EMAIL)
            .role(Role.ROLE_USER)
            .userStatus(UserStatus.BLOCKED)
            .build();
    }

    @Test
    void signUp() {
        User user = ModelUtils.getUser();
        UserVO userVO = ModelUtils.getUserVO();
        when(modelMapper.map(any(User.class), eq(UserVO.class))).thenReturn(userVO);
        when(userRepo.save(any(User.class))).thenReturn(user);
        when(jwtTool.generateTokenKey()).thenReturn("New-token-key");
        ownSecurityService.signUp(new OwnSignUpDto(), "en");
        verify(emailService, times(1)).sendVerificationEmail(
            refEq(user.getId()),
            refEq(user.getName()),
            refEq(user.getEmail()),
            refEq(user.getVerifyEmail().getToken()),
            refEq("en"), eq(false));
        verify(jwtTool, times(2)).generateTokenKey();
    }

    @Test
    void signUpThrowsUserAlreadyRegisteredExceptionTest() {
        OwnSignUpDto ownSignUpDto = new OwnSignUpDto();
        User user = User.builder().verifyEmail(new VerifyEmail()).build();
        UserVO userVO = UserVO.builder().verifyEmail(new VerifyEmailVO()).build();
        when(modelMapper.map(any(User.class), eq(UserVO.class))).thenReturn(userVO);
        when(jwtTool.generateTokenKey()).thenReturn("New-token-key");
        when(userRepo.save(any(User.class))).thenThrow(DataIntegrityViolationException.class);
        assertThrows(UserAlreadyRegisteredException.class,
            () -> ownSecurityService.signUp(ownSignUpDto, "en"));
    }

    @Test
    void signIn() {
        when(userService.findByEmail(anyString())).thenReturn(verifiedUser);
        when(passwordEncoder.matches(anyString(), anyString())).thenReturn(true);
        when(jwtTool.createAccessToken(anyString(), any(Role.class))).thenReturn("new-access-token");
        when(jwtTool.createRefreshToken(any(UserVO.class))).thenReturn("new-refresh-token");

        ownSecurityService.signIn(ownSignInDto);

        verify(userService, times(1)).findByEmail(anyString());
        verify(passwordEncoder, times(1)).matches(anyString(), anyString());
        verify(jwtTool, times(1)).createAccessToken(anyString(), any(Role.class));
        verify(jwtTool, times(1)).createRefreshToken(any(UserVO.class));
    }

    @Test
    void signInWithGoogleRejectsInvalidToken() throws GeneralSecurityException, IOException {
        when(googleIdTokenVerifier.verify("invalid-token")).thenReturn(null);

        assertThrows(
                BadRequestException.class,
                () -> ownSecurityService.signInWithGoogle("invalid-token")
        );

        verify(userService, never()).findByEmail(anyString());
    }

    @Test
    void signInWithGoogleRejectsUnverifiedEmail() throws GeneralSecurityException, IOException {
        when(googleIdTokenVerifier.verify("valid-token")).thenReturn(googleIdToken);
        when(googleIdToken.getPayload()).thenReturn(googlePayload);
        when(googlePayload.getEmail()).thenReturn("test@gmail.com");
        when(googlePayload.getEmailVerified()).thenReturn(false);

        assertThrows(
                BadRequestException.class,
                () -> ownSecurityService.signInWithGoogle("valid-token")
        );

        verify(userService, never()).findByEmail(anyString());
    }

    @Test
    void signInWithGoogleReturnsTokensForExistingUser() throws GeneralSecurityException, IOException {
        when(googleIdTokenVerifier.verify("valid-token")).thenReturn(googleIdToken);
        when(googleIdToken.getPayload()).thenReturn(googlePayload);
        when(googlePayload.getEmail()).thenReturn("test@gmail.com");
        when(googlePayload.getEmailVerified()).thenReturn(true);
        when(userService.findByEmail("test@gmail.com")).thenReturn(verifiedUser);
        when(jwtTool.createAccessToken("test@gmail.com", Role.ROLE_USER))
                .thenReturn("access-token");
        when(jwtTool.createRefreshToken(verifiedUser))
                .thenReturn("refresh-token");

        SuccessSignInDto result = ownSecurityService.signInWithGoogle("valid-token");

        assertEquals(1L, result.getUserId());
        assertEquals("access-token", result.getAccessToken());
        assertEquals("refresh-token", result.getRefreshToken());

        verify(userRepo, never()).save(any(User.class));
        verify(jwtTool).createAccessToken("test@gmail.com", Role.ROLE_USER);
        verify(jwtTool).createRefreshToken(verifiedUser);
    }

    @Test
    void signInWithGoogleCreatesUserAndReturnsTokens() throws GeneralSecurityException, IOException {
        String email = "new.user@gmail.com";

        when(googleIdTokenVerifier.verify("valid-token")).thenReturn(googleIdToken);
        when(googleIdToken.getPayload()).thenReturn(googlePayload);
        when(googlePayload.getEmail()).thenReturn(email);
        when(googlePayload.getEmailVerified()).thenReturn(true);
        when(googlePayload.get("name")).thenReturn("New User");
        when(userService.findByEmail(email)).thenReturn(null);

        when(jwtTool.generateTokenKey()).thenReturn("refresh-key");
        when(modelMapper.map(AppConstant.DEFAULT_LANGUAGE_CODE, Long.class)).thenReturn(2L);

        User savedUser = User.builder()
                .id(2L)
                .name("New User")
                .email(email)
                .role(Role.ROLE_USER)
                .userStatus(UserStatus.ACTIVATED)
                .refreshTokenKey("refresh-key")
                .build();

        UserVO newUserVO = UserVO.builder()
                .id(2L)
                .name("New User")
                .email(email)
                .role(Role.ROLE_USER)
                .userStatus(UserStatus.ACTIVATED)
                .refreshTokenKey("refresh-key")
                .build();

        when(userRepo.save(any(User.class))).thenReturn(savedUser);
        when(modelMapper.map(savedUser, UserVO.class)).thenReturn(newUserVO);
        when(jwtTool.createAccessToken(email, Role.ROLE_USER)).thenReturn("access-token");
        when(jwtTool.createRefreshToken(newUserVO)).thenReturn("refresh-token");

        SuccessSignInDto result = ownSecurityService.signInWithGoogle("valid-token");

        assertEquals(2L, result.getUserId());
        assertEquals("access-token", result.getAccessToken());
        assertEquals("refresh-token", result.getRefreshToken());

        ArgumentCaptor<User> userCaptor = forClass(User.class);
        verify(userRepo).save(userCaptor.capture());

        User createdUser = userCaptor.getValue();
        assertEquals(email, createdUser.getEmail());
        assertEquals("New User", createdUser.getName());
        assertEquals(Role.ROLE_USER, createdUser.getRole());
        assertEquals(UserStatus.ACTIVATED, createdUser.getUserStatus());
        assertEquals("refresh-key", createdUser.getRefreshTokenKey());
        assertEquals(2L, createdUser.getLanguage().getId());
        assertNotNull(createdUser.getUuid());
    }

    @ParameterizedTest
    @EnumSource(value = UserStatus.class, names = {"BLOCKED", "DEACTIVATED", "CREATED"})
    void signInWithGoogleRejectsInactiveUser(UserStatus status)
            throws GeneralSecurityException, IOException {
        String email = "test@gmail.com";

        when(googleIdTokenVerifier.verify("valid-token")).thenReturn(googleIdToken);
        when(googleIdToken.getPayload()).thenReturn(googlePayload);
        when(googlePayload.getEmail()).thenReturn(email);
        when(googlePayload.getEmailVerified()).thenReturn(true);

        UserVO user = UserVO.builder()
                .id(1L)
                .email(email)
                .role(Role.ROLE_USER)
                .userStatus(status)
                .build();
        when(userService.findByEmail(email)).thenReturn(user);

        assertThrows(
                BadUserStatusException.class,
                () -> ownSecurityService.signInWithGoogle("valid-token")
        );

        verify(jwtTool, never()).createAccessToken(anyString(), any(Role.class));
        verify(jwtTool, never()).createRefreshToken(any(UserVO.class));
        verify(userRepo, never()).save(any(User.class));
    }

    @Test
    void signInWithGoogleUsesEmailAsNameWhenGoogleNameIsMissing()
            throws GeneralSecurityException, IOException {
        String email = "new.user@gmail.com";
        mockVerifiedGoogleToken(email, null);
        when(userService.findByEmail(email)).thenReturn(null);
        when(jwtTool.generateTokenKey()).thenReturn("refresh-key");
        when(modelMapper.map(AppConstant.DEFAULT_LANGUAGE_CODE, Long.class)).thenReturn(2L);

        User savedUser = User.builder()
                .id(2L)
                .name("new.user")
                .email(email)
                .role(Role.ROLE_USER)
                .userStatus(UserStatus.ACTIVATED)
                .refreshTokenKey("refresh-key")
                .build();
        UserVO savedUserVO = UserVO.builder()
                .id(2L)
                .name("new.user")
                .email(email)
                .role(Role.ROLE_USER)
                .userStatus(UserStatus.ACTIVATED)
                .refreshTokenKey("refresh-key")
                .build();

        when(userRepo.save(any(User.class))).thenReturn(savedUser);
        when(modelMapper.map(savedUser, UserVO.class)).thenReturn(savedUserVO);
        when(jwtTool.createAccessToken(email, Role.ROLE_USER)).thenReturn("access-token");
        when(jwtTool.createRefreshToken(savedUserVO)).thenReturn("refresh-token");

        ownSecurityService.signInWithGoogle("valid-token");

        ArgumentCaptor<User> captor = ArgumentCaptor.forClass(User.class);
        verify(userRepo).save(captor.capture());
        assertEquals("new.user", captor.getValue().getName());
    }

    @Test
    void signInWithGoogleUsesEmailAsNameWhenGoogleNameIsNotString()
            throws GeneralSecurityException, IOException {
        String email = "new.user@gmail.com";
        mockVerifiedGoogleToken(email, 123);
        when(userService.findByEmail(email)).thenReturn(null);
        when(jwtTool.generateTokenKey()).thenReturn("refresh-key");
        when(modelMapper.map(AppConstant.DEFAULT_LANGUAGE_CODE, Long.class)).thenReturn(2L);

        User savedUser = User.builder()
                .id(2L)
                .name("new.user")
                .email(email)
                .role(Role.ROLE_USER)
                .userStatus(UserStatus.ACTIVATED)
                .refreshTokenKey("refresh-key")
                .build();
        UserVO savedUserVO = UserVO.builder()
                .id(2L)
                .name("new.user")
                .email(email)
                .role(Role.ROLE_USER)
                .userStatus(UserStatus.ACTIVATED)
                .refreshTokenKey("refresh-key")
                .build();

        when(userRepo.save(any(User.class))).thenReturn(savedUser);
        when(modelMapper.map(savedUser, UserVO.class)).thenReturn(savedUserVO);
        when(jwtTool.createAccessToken(email, Role.ROLE_USER)).thenReturn("access-token");
        when(jwtTool.createRefreshToken(savedUserVO)).thenReturn("refresh-token");

        ownSecurityService.signInWithGoogle("valid-token");

        ArgumentCaptor<User> captor = ArgumentCaptor.forClass(User.class);
        verify(userRepo).save(captor.capture());
        assertEquals("new.user", captor.getValue().getName());
    }

    @Test
    void signInWithGoogleRejectsEmailLongerThanDatabaseLimit()
            throws GeneralSecurityException, IOException {
        String email = "a".repeat(40) + "@example.com";
        mockVerifiedGoogleToken(email, "New User");

        assertThrows(
                BadRequestException.class,
                () -> ownSecurityService.signInWithGoogle("valid-token")
        );

        verify(userRepo, never()).save(any(User.class));
    }

    @Test
    void signInWithGoogleHandlesEmailAlreadyRegisteredDuringSave()
            throws GeneralSecurityException, IOException {
        String email = "new.user@gmail.com";
        mockVerifiedGoogleToken(email, "New User");
        when(userService.findByEmail(email)).thenReturn(null);
        when(jwtTool.generateTokenKey()).thenReturn("refresh-key");
        when(modelMapper.map(AppConstant.DEFAULT_LANGUAGE_CODE, Long.class)).thenReturn(2L);
        when(userRepo.save(any(User.class)))
                .thenThrow(new DataIntegrityViolationException("Duplicate email"));

        assertThrows(
                UserAlreadyRegisteredException.class,
                () -> ownSecurityService.signInWithGoogle("valid-token")
        );
    }


    @Test
    void signInNotVerifiedUser() {
        when(userService.findByEmail(anyString())).thenReturn(notVerifiedUser);
        when(passwordEncoder.matches(anyString(), anyString())).thenReturn(true);
        when(jwtTool.createAccessToken(anyString(), any(Role.class))).thenReturn("new-access-token");
        when(jwtTool.createRefreshToken(any(UserVO.class))).thenReturn("new-refresh-token");
        assertThrows(EmailNotVerified.class,
            () -> ownSecurityService.signIn(ownSignInDto));
    }

    @Test
    void signInNullUserTest() {
        when(userService.findByEmail("test@gmail.com")).thenReturn(null);
        assertThrows(WrongEmailException.class, () -> ownSecurityService.signIn(ownSignInDto));
    }

    @Test
    void signInWrongPasswordTest() {
        UserVO user = UserVO.builder()
            .email("test@gmail.com")
            .id(1L)
            .userStatus(UserStatus.ACTIVATED)
            .ownSecurity(null)
            .role(Role.ROLE_USER)
            .build();
        when(userService.findByEmail("test@gmail.com")).thenReturn(user);
        assertThrows(WrongPasswordException.class, () -> ownSecurityService.signIn(ownSignInDto));
    }

    @Test
    void signInDeactivatedUserTest() {
        UserVO user = UserVO.builder()
            .email("test@gmail.com")
            .id(1L)
            .userStatus(UserStatus.DEACTIVATED)
            .ownSecurity(OwnSecurityVO.builder().password("password").build())
            .role(Role.ROLE_USER)
            .build();
        when(userService.findByEmail("test@gmail.com")).thenReturn(user);
        when(passwordEncoder.matches("password", "password")).thenReturn(true);
        assertThrows(BadUserStatusException.class, () -> ownSecurityService.signIn(ownSignInDto));
    }

    @Test
    void signInBlockedUserTest() {
        UserVO user = UserVO.builder()
            .email("test@gmail.com")
            .id(1L)
            .userStatus(UserStatus.BLOCKED)
            .ownSecurity(OwnSecurityVO.builder().password("password").build())
            .role(Role.ROLE_USER)
            .build();
        when(userService.findByEmail("test@gmail.com")).thenReturn(user);
        when(passwordEncoder.matches("password", "password")).thenReturn(true);
        assertThrows(BadUserStatusException.class, () -> ownSecurityService.signIn(ownSignInDto));
    }

    @Test
    void signInCreatedUserTest() {
        UserVO user = UserVO.builder()
            .email("test@gmail.com")
            .id(1L)
            .userStatus(UserStatus.CREATED)
            .ownSecurity(OwnSecurityVO.builder().password("password").build())
            .role(Role.ROLE_USER)
            .build();
        when(userService.findByEmail("test@gmail.com")).thenReturn(user);
        when(passwordEncoder.matches("password", "password")).thenReturn(true);
        assertThrows(BadUserStatusException.class, () -> ownSecurityService.signIn(ownSignInDto));
    }

    @Test
    void updateAccessTokensTest() {
        when(jwtTool.getEmailOutOfAccessToken("12345")).thenReturn("test@gmail.com");
        when(userService.findByEmail("test@gmail.com")).thenReturn(verifiedUser);
        when(jwtTool.generateTokenKey()).thenReturn("token-key");
        when(jwtTool.isTokenValid("12345", verifiedUser.getRefreshTokenKey())).thenReturn(true);
        ownSecurityService.updateAccessTokens("12345");
        verify(jwtTool).createAccessToken(verifiedUser.getEmail(), verifiedUser.getRole());
        verify(jwtTool).createRefreshToken(verifiedUser);
    }

    @Test
    void updateAccessTokensBadRefreshTokenExceptionTest() {
        when(jwtTool.getEmailOutOfAccessToken("12345")).thenThrow(ExpiredJwtException.class);
        assertThrows(BadRefreshTokenException.class,
            () -> ownSecurityService.updateAccessTokens("12345"));
    }

    @Test
    void updateAccessTokensBadRefreshTokenTest() {
        when(jwtTool.getEmailOutOfAccessToken("12345")).thenReturn("test@gmail.com");
        when(userService.findByEmail("test@gmail.com")).thenReturn(verifiedUser);
        when(jwtTool.isTokenValid("12345", verifiedUser.getRefreshTokenKey())).thenReturn(false);
        assertThrows(BadRefreshTokenException.class,
            () -> ownSecurityService.updateAccessTokens("12345"));
    }

    @Test
    void updateAccessTokensBlockedUserTest() {
        verifiedUser.setUserStatus(UserStatus.BLOCKED);
        when(jwtTool.getEmailOutOfAccessToken("12345")).thenReturn("test@gmail.com");
        when(userService.findByEmail("test@gmail.com")).thenReturn(verifiedUser);
        assertThrows(UserBlockedException.class,
            () -> ownSecurityService.updateAccessTokens("12345"));
    }

    @Test
    void updateAccessTokensDeactivatedUserTest() {
        verifiedUser.setUserStatus(UserStatus.DEACTIVATED);
        when(jwtTool.getEmailOutOfAccessToken("12345")).thenReturn("test@gmail.com");
        when(userService.findByEmail("test@gmail.com")).thenReturn(verifiedUser);
        assertThrows(UserDeactivatedException.class,
            () -> ownSecurityService.updateAccessTokens("12345"));
    }

    @Test
    void updatePasswordTest() {
        when(passwordEncoder.encode("password")).thenReturn("encodedPassword");
        ownSecurityService.updatePassword("password", 1L);
        verify(ownSecurityRepo).updatePassword("encodedPassword", 1L);
    }

    @Test
    void updateCurrentPasswordTest() {
        when(userService.findByEmail("test@gmail.com")).thenReturn(verifiedUser);
        when(passwordEncoder.encode(updatePasswordDto.getPassword())).thenReturn(updatePasswordDto.getPassword());
        ownSecurityService.updateCurrentPassword(updatePasswordDto, "test@gmail.com");
        verify(ownSecurityRepo).updatePassword(updatePasswordDto.getPassword(), 1L);
    }

    @Test
    void updateCurrentPasswordDifferentPasswordsTest() {
        updatePasswordDto.setPassword("123");
        when(userService.findByEmail("test@gmail.com")).thenReturn(verifiedUser);
        assertThrows(PasswordsDoNotMatchesException.class,
            () -> ownSecurityService.updateCurrentPassword(updatePasswordDto, "test@gmail.com"));
    }

    @Test
    void updateCurrentPasswordEmailNotVerifiedTest() {
        updatePasswordDto.setPassword("123");

        UserVO user = ModelUtils.getUserVO();
        user.setUserStatus(UserStatus.CREATED);

        when(userService.findByEmail("test@gmail.com")).thenReturn(user);

        assertThrows(EmailNotVerified.class,
            () -> ownSecurityService.updateCurrentPassword(updatePasswordDto, "test@gmail.com"));
    }

    @Test
    void managementRegisterUserTest() {
        User user = ModelUtils.getUser();
        user.setUserStatus(UserStatus.BLOCKED);
        user.setLanguage(Language.builder().id(2L).code("en").build());
        user.setDateOfRegistration(LocalDateTime.of(2020, 6, 6, 13, 47));

        UserAdminRegistrationDto dto = ModelUtils.getUserAdminRegistrationDto();
        when(jwtTool.generateTokenKey()).thenReturn("token-key");
        when(userRepo.findByEmail(anyString())).thenReturn(Optional.empty());
        when(userRepo.save(any())).thenReturn(user);
        when(modelMapper.map(user, UserAdminRegistrationDto.class)).thenReturn(dto);

        UserAdminRegistrationDto expected = ownSecurityService.managementRegisterUser(userManagementDto);

        assertEquals(dto, expected);

        verify(restorePasswordEmailRepo, times(1)).save(any());
        verify(emailService).sendApprovalEmail(1L, TestConst.NAME, TestConst.EMAIL, "token-key");
    }

    @Test
    void managementRegisterUserShouldThrowUserAlreadyRegisteredException() {
        when(userRepo.findByEmail(any())).thenReturn(Optional.of(ModelUtils.getUser()));

        Exception thrown = assertThrows(UserAlreadyRegisteredException.class,
            () -> ownSecurityService.managementRegisterUser(userManagementDto));

        assertEquals(ErrorMessage.USER_ALREADY_REGISTERED_WITH_THIS_EMAIL, thrown.getMessage());
    }

    @Test
    void hasPasswordTrue() {
        User user = ModelUtils.getUser();
        user.setOwnSecurity(ModelUtils.TEST_OWN_SECURITY);
        when(userRepo.findByEmail(user.getEmail())).thenReturn(Optional.of(user));
        assertTrue(ownSecurityService.hasPassword(user.getEmail()));
    }

    @Test
    void hasPasswordFalse() {
        User user = ModelUtils.getUser();
        when(userRepo.findByEmail(user.getEmail())).thenReturn(Optional.of(user));
        assertFalse(ownSecurityService.hasPassword(user.getEmail()));
    }

    @Test
    void hasPasswordWrongEmailException() {
        when(userRepo.findByEmail(anyString())).thenReturn(Optional.empty());
        assertThrows(WrongEmailException.class, () -> ownSecurityService.hasPassword(""));
    }

    @Test
    void setPassword() {
        SetPasswordDto dto = SetPasswordDto.builder()
            .password(ModelUtils.TEST_OWN_RESTORE_DTO.getPassword())
            .confirmPassword(ModelUtils.TEST_OWN_RESTORE_DTO.getConfirmPassword())
            .build();
        User user = ModelUtils.getUser();
        when(userRepo.findByEmail(user.getEmail())).thenReturn(Optional.of(user));

        ownSecurityService.setPassword(dto, user.getEmail());

        assertNotNull(user.getOwnSecurity());
        verify(userRepo).save(user);
    }

    @Test
    void setPasswordWrongEmailException() {
        SetPasswordDto dto = SetPasswordDto.builder().build();
        when(userRepo.findByEmail(anyString())).thenReturn(Optional.empty());

        assertThrows(WrongEmailException.class, () -> ownSecurityService.setPassword(dto, ""));
    }

    @Test
    void setPasswordUserAlreadyHasPasswordException() {
        SetPasswordDto dto = SetPasswordDto.builder().build();
        User user = ModelUtils.getUser();
        user.setOwnSecurity(ModelUtils.TEST_OWN_SECURITY);
        String email = user.getEmail();

        when(userRepo.findByEmail(email)).thenReturn(Optional.of(user));

        assertThrows(UserAlreadyHasPasswordException.class, () -> ownSecurityService.setPassword(dto, email));
    }

    @Test
    void setPasswordPasswordsDoNotMatchesException() {
        SetPasswordDto dto = SetPasswordDto.builder()
            .password(ModelUtils.TEST_OWN_RESTORE_DTO_WRONG.getPassword())
            .confirmPassword(ModelUtils.TEST_OWN_RESTORE_DTO_WRONG.getConfirmPassword())
            .build();
        User user = ModelUtils.getUser();
        String email = user.getEmail();

        when(userRepo.findByEmail(email)).thenReturn(Optional.of(user));

        assertThrows(PasswordsDoNotMatchesException.class, () -> ownSecurityService.setPassword(dto, email));
    }
}
