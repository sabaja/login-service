package com.login.controller.model;

import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;

import java.io.Serializable;
import java.util.Collection;

@Getter
@Setter
public class CourseUser extends org.springframework.security.core.userdetails.User implements Serializable {

    private String nickname;

    public CourseUser(String username, String nickname, String password, Collection<? extends GrantedAuthority> authorities) {
        super(username, password, authorities);
        this.nickname = nickname;
    }

    public CourseUser(String username, String password, Collection<? extends GrantedAuthority> authorities) {
        super(username, password, authorities);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof CourseUser that)) return false;
        if (!super.equals(o)) return false;

        return getNickname() != null ? getNickname().equals(that.getNickname()) : that.getNickname() == null;
    }

    @Override
    public int hashCode() {
        int result = super.hashCode();
        result = 31 * result + (getNickname() != null ? getNickname().hashCode() : 0);
        return result;
    }
}
