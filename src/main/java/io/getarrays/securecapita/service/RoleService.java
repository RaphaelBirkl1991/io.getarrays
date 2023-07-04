package io.getarrays.securecapita.service;

import io.getarrays.securecapita.domain.Role;

public interface RoleService {
    Role getRoleByUserId(Long id);
}
