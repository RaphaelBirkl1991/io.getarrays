package io.getarrays.securecapita.service.implementation;

import io.getarrays.securecapita.domain.Role;
import io.getarrays.securecapita.domain.User;
import io.getarrays.securecapita.dto.UserDTO;
import io.getarrays.securecapita.repository.RoleRepository;
import io.getarrays.securecapita.repository.UserRepository;
import io.getarrays.securecapita.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import static io.getarrays.securecapita.dtomapper.UserDTOMapper.fromUser;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {
    private final UserRepository<User> userRepository;
    private final RoleRepository<Role> roleRoleRepository;
    @Override
    public UserDTO createUser(User user) {
        return mapToUserDTO(userRepository.create(user));
    }

    @Override
    public UserDTO getUserByEmail(String email) {
        return mapToUserDTO(userRepository.getUserByEmail(email));
    }

    @Override
    public void sendVerificationCode(UserDTO user) {
    userRepository.sendVerficationCode(user);
    }



    @Override
    public UserDTO verifyCode(String email, String code) {
        return fromUser(userRepository.verifyCode(email, code));
    }


    private UserDTO mapToUserDTO(User user){
        return fromUser(user, roleRoleRepository.getRoleByUserId(user.getId()));
    }

}
