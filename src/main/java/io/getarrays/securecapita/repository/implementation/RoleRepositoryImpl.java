package io.getarrays.securecapita.repository.implementation;

import io.getarrays.securecapita.domain.Role;
import io.getarrays.securecapita.exception.ApiException;
import io.getarrays.securecapita.repository.RoleRepository;
import io.getarrays.securecapita.rowmapper.RoleRowMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Repository;

import java.util.Collection;

import static io.getarrays.securecapita.enumeration.RoleType.ROLE_USER;
import static io.getarrays.securecapita.query.RoleQuery.*;
import static java.util.Map.of;
import static java.util.Objects.requireNonNull;

@Repository
@RequiredArgsConstructor
@Slf4j
public class RoleRepositoryImpl implements RoleRepository<Role> {

    private final NamedParameterJdbcTemplate jdbc;
    @Override
    public Role create(Role data) {
        return null;
    }

    @Override
    public Collection<Role> list(int page, int pageSize) {
        return null;
    }

    @Override
    public Role get(Long id) {
        return null;
    }

    @Override
    public Role update(Role data) {
        return null;
    }

    @Override
    public Boolean delete(Long id) {
        return null;
    }

@Override
public void addRoleToUser(Long userId, String roleName) {
    log.info("Adding role {} to user id: {}", roleName, userId);
    try {
        Role role = jdbc.queryForObject(SELECT_ROLE_BY_NAME_QUERY, of("name", roleName), new RoleRowMapper());
        jdbc.update(INSERT_ROLE_TO_USER_QUERY, of("userId", userId, "roleId", requireNonNull(role).getId()));
    } catch (EmptyResultDataAccessException exception) {
        throw new ApiException("No role found by name: " + ROLE_USER.name());

    } catch (Exception exception) {
        log.error(exception.getMessage());
        throw new ApiException("An error occurred. Please try again.");
    }

}
@Override
public Role getRoleByUserId(Long userId) {
    log.info("method: getRoleByUserId: Adding role for user id: {}", userId);
    try {
        return jdbc.queryForObject(SELECT_ROLE_BY_ID_QUERY, of("id", userId), new RoleRowMapper());
    } catch (EmptyResultDataAccessException exception) {
        log.warn("we are in catch of method getRoleByUserId");
        throw new ApiException("No role found by name: " + ROLE_USER.name());
    } catch (Exception exception) {
        log.error(exception.getMessage());
        throw new ApiException("An error occurred. Please try again.");
    }
}
    @Override
    public Role getRoleByUserEmail(String email) {
        return null;
    }

    @Override
    public void updateUserRole(Long userId, String roleName) {

    }
}
