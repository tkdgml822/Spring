package com.mysite.sbb.user;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@RequiredArgsConstructor
@Service
public class UserSecurityService implements UserDetailsService {

    private final UserRepository userRepository;

    // loadUserByUsername은 사용자명으로 비밀번호를 조회하여 리터하는 메서드이다.
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<SiteUser> _siteUser = this.userRepository.findByusername(username);
        if (_siteUser.isEmpty()) {
            throw  new UsernameNotFoundException("사용자를 찾을수 없습니다."); // 사용자에 관한 데이터가 없으면 UsernameNotFoundException오류 발생
        }

        SiteUser siteUser = _siteUser.get();
        List<GrantedAuthority> authorities = new ArrayList<>();

        // 사용자가 admin인 경우
        if ("admin".equals(username)) {
            authorities.add(new SimpleGrantedAuthority(UserRole.ADMIN.getValue())); // ADMIN 권한을 부여
        }
        // 아닌 경우
        else {
            authorities.add(new SimpleGrantedAuthority(UserRole.USER.getValue())); // USER 권한 부여
        }

        // 사용자명 , 비밀번호, 권한을 User객체를 생성하여 리턴한다.
        // 스프링 시큐리티는 loadUserByUsername 메서드에 의해 리턴된
        // User 객체의 비밀번호가 화면으로부터 입력 받은 비밀번호와 일치하는지 검사하는 내부적인 로직을 가지고 있다.
        return new User(siteUser.getUsername(), siteUser.getPassword(), authorities);
    }

}
