package com.login.entity;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

public interface RoleHierarchyRepository extends JpaRepository<RoleHierarchy, Long> {

    @Query("SELECT r.hierarchy FROM RoleHierarchy r")
    String getHierarchy();
}