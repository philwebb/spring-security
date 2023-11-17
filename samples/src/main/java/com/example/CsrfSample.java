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
import org.springframework.security.lambdaconfig.web.SecurityFilterChainContribution;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.util.matcher.RequestMatcher;

public class CsrfSample {

	private RequestMatcher myMatcher;

	private CsrfTokenRepository myTokenRepo;

	SecurityFilterChain example(HttpSecurity httpSecurity) throws Exception {
		httpSecurity.csrf((csrfCustomizer) -> {
			csrfCustomizer.ignoringRequestMatchers("/foo/**");
			csrfCustomizer.ignoringRequestMatchers("/bar/**");
			csrfCustomizer.requireCsrfProtectionMatcher(this.myMatcher);
			csrfCustomizer.csrfTokenRepository(this.myTokenRepo);
		});
		return httpSecurity.build();
	}

	SecurityFilterChain exampleLambda() {
		return HttpSecurityFilterChain.of((chain) -> {
			chain.csrf((csrf) -> {
				csrf.apply().whenMatches(this.myMatcher).ignoring("/foo/**").ignoring("/bar/**");
				csrf.tokenRepository(this.myTokenRepo);
			});
		});
	}

	SecurityFilterChain disable(HttpSecurity httpSecurity) throws Exception {
		httpSecurity.csrf((csrfCustomizer) -> csrfCustomizer.disable());
		return httpSecurity.build();
	}

	SecurityFilterChain disableLambda() {
		return HttpSecurityFilterChain.of((chain) -> {
			chain.csrf((csrf) -> csrf.disable());
			// or
			chain.csrf(SecurityFilterChainContribution::disable);
		});
	}

}
