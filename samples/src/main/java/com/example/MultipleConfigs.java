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

package com.example;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.lambdaconfig.web.HttpSecurityFilterChain;
import org.springframework.security.lambdaconfig.web.SessionManagementContributor.Configurer.Policy;
import org.springframework.security.web.SecurityFilterChain;

public class MultipleConfigs {

	// https://www.danvega.dev/blog/2023/04/20/multiple-spring-security-configs

	// @Order(1)
	SecurityFilterChain apiSecurityFilterChain(HttpSecurity http) {
		return HttpSecurityFilterChain.of((chain) -> {
			chain.apply().ifMatches("/api/**");
			chain.authorizationRules().ifAnyRequest().thenReturnChecking().isAuthenticated();
			chain.sessionManagement().policy(Policy.DISABLE);
			chain.httpBasic();
		});
	}

	// @Order(2)
	SecurityFilterChain h2ConsoleSecurityFilterChain(HttpSecurity http) {
		return HttpSecurityFilterChain.of((chain) -> {
			chain.apply().ifMatches("/h2-console/**");
			chain.authorizationRules().ifMatches("/h2-console/**").thenReturnPermitted();
			chain.csrf().apply().ignoring("/h2-console/**");
			chain.headers().frameOptions().disable();
		});
	}

	// @Order(3)
	SecurityFilterChain securityFilterChain(HttpSecurity http) {
		return HttpSecurityFilterChain.of((chain) -> {
			chain.authorizationRules((authorizeRequests) -> {
				authorizeRequests.ifMatches("/", "/error").thenReturnPermitted();
				authorizeRequests.ifAnyRequest().thenReturnChecking().isAuthenticated();
			});
			chain.formLogin();
		});
	}

}
