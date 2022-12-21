package com.login.controller.model;

import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Getter
@Setter
public class CourseUser extends org.springframework.security.core.userdetails.User implements Serializable {

    private String nickname;
    private String username;
    private String password;
    private List<GrantedAuthority> grantedAuthorities;

    public CourseUser(String username, String nickname, String password, Collection<? extends GrantedAuthority> authorities) {
        super(username, password, authorities);
        this.username = username;
        this.nickname = nickname;
        this.password = password;
        this.grantedAuthorities = new ArrayList<>(authorities);
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
