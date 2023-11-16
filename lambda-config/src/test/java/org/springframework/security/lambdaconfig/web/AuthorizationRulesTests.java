/*
 * Copyright 2023 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.lambdaconfig.web;

import jakarta.servlet.DispatcherType;
import org.junit.jupiter.api.Test;

import org.springframework.security.lambdaconfig.web.XRequestAuthorizations;

import static org.springframework.security.authorization.AuthorityAuthorizationManager.hasAuthority;
import static org.springframework.security.authorization.AuthorityAuthorizationManager.hasRole;
import static org.springframework.security.authorization.AuthorizationManagers.allOf;

/**
 * @author pwebb
 */
class AuthorizationRulesTests {

	@Test
	void test() {
		XRequestAuthorizations authorizations = null;
		authorizations.permit().whenMatches(DispatcherType.FORWARD);
		authorizations.permitIfFullyAuthenticated().whenMatches("/foo");
		authorizations.deny();

		// http
		// .authorizeHttpRequests((requests) -> requests
		// .requestMatchers("/", "/home").permitAll()
		// .anyRequest().authenticated()
		// )

		authorizations.permit().whenMatches("/", "/home");
		authorizations.permitIfAuthenticated();

		//@formatter:off
		/*
@Bean
SecurityFilterChain web(HttpSecurity http) throws Exception {
	http
		// ...
		.authorizeHttpRequests(authorize -> authorize
            .dispatcherTypeMatchers(FORWARD, ERROR).permitAll()
			.requestMatchers("/static/**", "/signup", "/about").permitAll()
			.requestMatchers("/admin/**").hasRole("ADMIN")
			.requestMatchers("/db/**").access(allOf(hasAuthority('db'), hasRole('ADMIN')))
			.anyRequest().denyAll()
		);

	return http.build();
		 */
		   //@formatter:on

		authorizations.permit().whenMatches(DispatcherType.FORWARD, DispatcherType.ERROR);
		authorizations.permit().whenMatches("/static/**", "/signup", "/about");
		authorizations.permitIfHasRole("ADMIN").whenMatches("/admin/**");
		authorizations.check(allOf(hasAuthority("db"), hasRole("ADMIN"))).whenMatches("/db/**");

		authorizations.deny();

		//@formatter:off

		/*

  http
                .authorizeRequests()
                .antMatchers("/js/**", "/css/**")
                .permitAll();

        http
                .authorizeRequests()
                .antMatchers("/api/**")
                .authenticated()
                .and()
                .httpBasic();

        http
                .authorizeRequests()
                .antMatchers("/","/index")
                .authenticated()
                .and()
                .formLogin()
                .loginPage("/login")
                .loginProcessingUrl("/j_spring_security_check")
                .defaultSuccessUrl("/monitor")
                .failureUrl("/login?error")
                .usernameParameter("j_username")
                .passwordParameter("j_password")
                .permitAll()
                .and()
                .logout()
                .logoutUrl("/j_spring_security_logout")
                .logoutSuccessUrl("/login?logout")
                .permitAll()
                .and()
                .csrf()
                .disable();


		*/
		//@formatter:on

		authorizations.permit().whenMatches("/js/**", "/css/**");
		authorizations.permitIfAuthenticated().whenMatches("/**");
		authorizations.permitIfAuthenticated().whenMatches("/", "/index");
	}

}
