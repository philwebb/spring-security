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
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

public class LogoutSample {

	private LogoutSuccessHandler myHandler;

	SecurityFilterChain example(HttpSecurity httpSecurity) throws Exception {
		httpSecurity.logout((logout) -> {
			logout.permitAll();
			logout.logoutUrl("/foo");
			logout.logoutRequestMatcher(new AntPathRequestMatcher("/foo/**"));
			logout.defaultLogoutSuccessHandlerFor(this.myHandler, new AntPathRequestMatcher("/foo/**"));
		});
		return httpSecurity.build();
	}

	SecurityFilterChain exampleLambda() {
		return HttpSecurityFilterChain.of((chain) -> {
			chain.logout((logout) -> {
				logout.permitRequests();
				logout.url("foo");
				logout.apply().whenMatches("/foo/**");
				logout.addSuccessHandler(this.myHandler).whenMatches("/foo/**");
			});
		});
	}

}
