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

import jakarta.servlet.DispatcherType;

import org.springframework.http.HttpMethod;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.lambdaconfig.web.HttpSecurityFilterChain;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

public class AuthorizationRulesSample {

	private AuthorizationManager<RequestAuthorizationContext> manager;

	SecurityFilterChain multipleItems(HttpSecurity httpSecurity) throws Exception {
		httpSecurity.authorizeHttpRequests((authorize) -> {
			authorize.requestMatchers("/foo/**").authenticated();
			authorize.requestMatchers("/bar/**").fullyAuthenticated();
			authorize.dispatcherTypeMatchers(DispatcherType.FORWARD).permitAll();
			authorize.anyRequest().denyAll();
		});
		return httpSecurity.build();
	}

	SecurityFilterChain multipleItemsChained(HttpSecurity httpSecurity) throws Exception {
		httpSecurity.authorizeHttpRequests((authorize) -> {
			authorize.requestMatchers("/foo/**")
				.authenticated()
				.requestMatchers("/bar/**")
				.fullyAuthenticated()
				.dispatcherTypeMatchers(DispatcherType.FORWARD)
				.permitAll()
				.anyRequest()
				.denyAll();
		});
		return httpSecurity.build();
	}

	SecurityFilterChain specificHandlerLambda() {
		return HttpSecurityFilterChain.of((chain) -> {
			chain.authorizationRules((authorizationRules) -> {
				authorizationRules.ifMatches("/foo/**").thenReturnChecking().isAuthenticated();
				authorizationRules.ifMatches("/bar/**").thenReturnChecking().isFullyAuthenticated();
				authorizationRules.ifMatches(DispatcherType.FORWARD).thenReturnPermitted();
				authorizationRules.ifAnyRequest().thenReturnDenied();
			});
		});
	}

	SecurityFilterChain custom(HttpSecurity httpSecurity) throws Exception {
		httpSecurity.authorizeHttpRequests((authorize) -> {
			authorize.requestMatchers(HttpMethod.PATCH).access(this.manager);
			authorize.anyRequest().access(this.manager);
		});
		return httpSecurity.build();
	}

	SecurityFilterChain customLambda() {
		return HttpSecurityFilterChain.of((chain) -> {
			chain.authorizationRules((authorizationRules) -> {
				authorizationRules.ifMatches(HttpMethod.PATCH).thenReturnChecking(this.manager);
				authorizationRules.ifAnyRequest().thenReturnChecking(this.manager);
			});
		});
	}

}
