package io.security.basicsecurity;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

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
			.formLogin()
			//.loginPage("/loginPage") //사용자가 로그인 할 수 있도록 제공되는 페이지 (= 해당 페이지는 인증 없이 접근 가능)
			.defaultSuccessUrl("/")
			.failureUrl("/login")
			.usernameParameter("userId")
			.passwordParameter("passwd")
			.loginProcessingUrl("/login_proc")
			.successHandler(new AuthenticationSuccessHandler() {
				
				@Override
				public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
						Authentication authentication) throws IOException, ServletException {
					System.out.println("authentication" + authentication.getName()); //인증 성공한 사용자명
					response.sendRedirect("/"); //인증 후 root 페이지로 이동
					
				}
			})
			.failureHandler(new AuthenticationFailureHandler() {
				
				@Override
				public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
						AuthenticationException exception) throws IOException, ServletException {
					System.out.println("exception" + exception.getMessage());
					response.sendRedirect("/login");
				}
			})
			.permitAll(); //해당 페이지(/loginPage)는 누구나 접근 가능할 수 있도록 설정
	}
}