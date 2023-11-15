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
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.util.matcher.RequestMatcher;

public class ExceptionHandlingSample {

	AccessDeniedHandler myHandler1 = null;

	AccessDeniedHandler myHandler2 = null;

	RequestMatcher myRequestMatcher1 = null;

	RequestMatcher myRequestMatcher2 = null;

	SecurityFilterChain specificHandler(HttpSecurity httpSecurity) throws Exception {
		httpSecurity.exceptionHandling((exceptionHandling) -> {
			exceptionHandling.accessDeniedHandler(this.myHandler1);
		});
		return httpSecurity.build();
	}

	SecurityFilterChain specificHandlerLambda() {
		return HttpSecurityFilterChain.of((chain) -> {
			chain.exceptionHandling().addAccessDeniedHandler(this.myHandler1);
		});
	}

	SecurityFilterChain defaultHandlers(HttpSecurity httpSecurity) throws Exception {
		httpSecurity.exceptionHandling((exceptionHandling) -> {
			exceptionHandling.defaultAccessDeniedHandlerFor(this.myHandler1, null);
		});
		return httpSecurity.build();
	}

	SecurityFilterChain defaultHandlersLambda() {
		return HttpSecurityFilterChain.of((chain) -> {
			chain.exceptionHandling((exceptionHandling) -> {
				exceptionHandling.addAccessDeniedHandler(this.myHandler1).whenMatches(this.myRequestMatcher1);
				exceptionHandling.addAccessDeniedHandler(this.myHandler2).whenMatches(this.myRequestMatcher2);
				// Can also do
				exceptionHandling.addAccessDeniedHandler(this.myHandler1).whenMatches("/foo/**");
			});
		});
	}

}
