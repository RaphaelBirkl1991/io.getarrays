package io.getarrays.securecapita.service.implementation;

import io.getarrays.securecapita.domain.Role;
import io.getarrays.securecapita.repository.RoleRepository;
import io.getarrays.securecapita.service.RoleService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class RoleServiceImpl implements RoleService {
    private final RoleRepository<Role> roleRoleRepository;
    @Override
    public Role getRoleByUserId(Long id) {
         return roleRoleRepository.getRoleByUserId(id);
    }

}
