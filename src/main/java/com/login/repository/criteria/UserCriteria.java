package com.login.repository.criteria;

import com.login.entity.User;

import java.util.List;

public interface UserCriteria {
    List<User> getLongTermUsers(User user);
}
