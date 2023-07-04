package io.getarrays.securecapita.service;

import io.getarrays.securecapita.domain.User;
import io.getarrays.securecapita.dto.UserDTO;

public interface UserService {
    UserDTO createUser(User user);
    UserDTO getUserByEmail(String email);
    void sendVerificationCode(UserDTO user);


    UserDTO verifyCode(String email, String code);
}
