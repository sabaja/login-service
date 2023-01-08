package com.login.config;

import com.login.entity.RoleHierarchyRepository;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.stereotype.Component;

@Component
public class CustomRoleHierarchy extends RoleHierarchyImpl {
    @Autowired
    private RoleHierarchyRepository roleRepository;

    @PostConstruct
    public void init() {
        String hierarchy = roleRepository.getHierarchy();
        setHierarchy(hierarchy);
    }
}