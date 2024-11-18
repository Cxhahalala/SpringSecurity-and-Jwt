package com.example.security.user;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

@Data
// @builder，为类生成 Builder 模式，让我们可以更加优雅和灵活地构造对象。
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "_user")
public class User implements UserDetails {
    //自动生成主键
    @Id
    @GeneratedValue
    private Integer id;
    private String firstname;

    protected String lastname;

    private String email;

    private String password;
    //@Enumerated 指示字段为枚举类型，EnumType.ORDINAL,将枚举的序号保存数据库，EnumType.STRING将枚举的名称保存数据库
    @Enumerated(EnumType.STRING)
    private Role role;
    // 返回一个简单的授权权限,返回角色名称
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority(role.name()));
    }

    @Override
    public String getPassword() {
        return password;
    }

    //获取用户名称,本案例即是email
    @Override
    public String getUsername() {
        return email;
    }
    // 账户是否过期，未过期true，过期false
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }
    //账户是否被锁定，未被锁定true,被锁定false
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
