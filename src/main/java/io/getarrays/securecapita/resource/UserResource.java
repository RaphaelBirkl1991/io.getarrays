package io.getarrays.securecapita.resource;

import io.getarrays.securecapita.domain.HttpResponse;
import io.getarrays.securecapita.domain.User;
import io.getarrays.securecapita.domain.UserPrincipal;
import io.getarrays.securecapita.dto.UserDTO;
import io.getarrays.securecapita.form.LoginForm;
import io.getarrays.securecapita.provider.TokenProvider;
import io.getarrays.securecapita.service.RoleService;
import io.getarrays.securecapita.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.net.URI;
import java.util.Map;

import static io.getarrays.securecapita.dtomapper.UserDTOMapper.toUser;
import static java.time.LocalTime.now;
import static org.springframework.http.HttpStatus.CREATED;
import static org.springframework.http.HttpStatus.OK;


@RestController
@RequestMapping(path = "/user")
@RequiredArgsConstructor
public class UserResource {
    private final UserService userService;
    private final RoleService roleService;
    private final AuthenticationManager authenticationManager;
    private final TokenProvider tokenProvider;


    @PostMapping("/login")
    public ResponseEntity<HttpResponse> login(@RequestBody @Valid LoginForm loginForm) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginForm.getEmail(), loginForm.getPassword() ));
        UserDTO user = userService.getUserByEmail(loginForm.getEmail());
        return user.isUsingMfa() ? sendVerificationCode(user) : sendResponse(user);
    }

    @PostMapping("/register")
    public ResponseEntity<HttpResponse> saveUser(@RequestBody @Valid User user) {
        UserDTO userDTO = userService.createUser(user);
        return ResponseEntity.created(getUri()).body(
                HttpResponse.builder()
                        .timeStamp(now().toString())
                        .data(Map.of("user", userDTO))
                        .message("user created")
                        .status(CREATED)
                        .statusCode(CREATED.value())
                        .build());
    }

    @GetMapping("/verify/code/{email}/{code}")
    public ResponseEntity<HttpResponse> verifyCode(@PathVariable("email") String email, @PathVariable("code") String code){
        UserDTO user = userService.verifyCode(email, code);
        return ResponseEntity.ok().body(
                HttpResponse.builder()
                        .timeStamp(now().toString())
                        .data(Map.of("user", user, "access_token", tokenProvider.createAccessToken(getUserPrincipal(user))
                                ,"refresh_token", tokenProvider.createRefreshToken(getUserPrincipal(user))))
                        .message("Login Success")
                        .status(OK)
                        .statusCode(OK.value())
                        .build());
    }

    private URI getUri() {
        return URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/user/get/<userId>").toUriString());
    }
    private ResponseEntity<HttpResponse> sendResponse(UserDTO user) {
        return ResponseEntity.ok().body(
                HttpResponse.builder()
                        .timeStamp(now().toString())
                        .data(Map.of("user", user, "access_token", tokenProvider.createAccessToken(getUserPrincipal(user))
                        ,"refresh_token", tokenProvider.createRefreshToken(getUserPrincipal(user))))
                        .message("Login Success")
                        .status(OK)
                        .statusCode(OK.value())
                        .build());
    }

    private UserPrincipal getUserPrincipal(UserDTO user) {
       // return new UserPrincipal(userService.getUser(user.getEmail()), roleService.getRoleByUserId(user.getId()).getPermission());
        return new UserPrincipal(toUser(userService.getUserByEmail(user.getEmail())), roleService.getRoleByUserId(user.getId()).getPermission());
    }

    private ResponseEntity<HttpResponse> sendVerificationCode(UserDTO user) {
        userService.sendVerificationCode(user);
        return ResponseEntity.ok().body(
                HttpResponse.builder()
                        .timeStamp(now().toString())
                        .data(Map.of("user", user))
                        .message("Verification Code Sent")
                        .status(OK)
                        .statusCode(OK.value())
                        .build());
    }

}