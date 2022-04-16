package io.security.basicsecurity;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter{
	
	@Override
	protected void configure(HttpSecurity http) throws Exception{
		//API 인가 정책
		http
			.authorizeRequests() //요청에 대한 보안 실행
			.anyRequest().authenticated(); //어떤 요청에도 인증 받도록 설정
		
		//API 인증 정책
		http
			.formLogin();
		
		http
			.logout()
			.logoutUrl("/logout")
			.logoutSuccessUrl("/login") //로그아웃 후 이동할 페이지
			.addLogoutHandler(new LogoutHandler() {
				
				@Override
				public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
					HttpSession session = request.getSession();
					session.invalidate(); //세션 무효화
				}
			})
			
			//로그아웃 후 구현할 로직
			.logoutSuccessHandler(new LogoutSuccessHandler() {
				
				@Override
				public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
						throws IOException, ServletException {
					response.sendRedirect("/login");					
				}
			})
			.deleteCookies("remember-me");
	}
}