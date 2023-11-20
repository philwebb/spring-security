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

import java.time.Duration;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.lambdaconfig.web.HttpSecurityFilterChain;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.header.writers.CrossOriginEmbedderPolicyHeaderWriter.CrossOriginEmbedderPolicy;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

public class HeadersSample {

	SecurityFilterChain example(HttpSecurity httpSecurity) throws Exception {
		httpSecurity.headers((headers) -> {
			headers.contentTypeOptions((contentTypeOptionsCustomizer) -> contentTypeOptionsCustomizer.disable());
			headers.defaultsDisabled();
			headers.cacheControl((cacheControlCustomizer) -> {
			});
			headers.crossOriginEmbedderPolicy((crossOriginEmbedderPolicyCustomizer) -> {
				crossOriginEmbedderPolicyCustomizer.policy(CrossOriginEmbedderPolicy.REQUIRE_CORP);
			});
			headers.httpStrictTransportSecurity((hsts) -> {
				hsts.maxAgeInSeconds(1);
				hsts.requestMatcher(new AntPathRequestMatcher("/foo/**"));
			});
		});
		return httpSecurity.build();
	}

	SecurityFilterChain exampleLambda() {
		return HttpSecurityFilterChain.of((chain) -> {
			chain.headers((headers) -> {
				headers.contentTypeOptions().disable();
				headers.disableAll();
				headers.cacheControl();
				headers.crossOriginEmbedder().policy(CrossOriginEmbedderPolicy.REQUIRE_CORP);
				headers.httpStrictTransportSecurity((hsts) -> {
					hsts.maxAge(Duration.ofSeconds(1));
					hsts.apply().ifMatches("/foo/**");
				});
			});
		});
	}

}
