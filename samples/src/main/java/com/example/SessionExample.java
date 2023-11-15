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
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.lambdaconfig.web.HttpSecurityFilterChain;
import org.springframework.security.lambdaconfig.web.SessionManagementContributor.Configurer.Fixation;
import org.springframework.security.lambdaconfig.web.SessionManagementContributor.Configurer.Policy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.session.SessionInformationExpiredStrategy;

public class SessionExample {

	private SessionInformationExpiredStrategy mySessionExpiredStrategy;

	SecurityFilterChain example(HttpSecurity httpSecurity) throws Exception {
		httpSecurity.sessionManagement((sessionManagement) -> {
			sessionManagement.sessionCreationPolicy(SessionCreationPolicy.NEVER);
			sessionManagement.maximumSessions(10);
			sessionManagement.sessionFixation().migrateSession();
			sessionManagement.enableSessionUrlRewriting(true);
			sessionManagement.sessionConcurrency((concurrency) -> {
				concurrency.maxSessionsPreventsLogin(true);
				concurrency.expiredSessionStrategy(this.mySessionExpiredStrategy);
			});
		});
		return httpSecurity.build();
	}

	SecurityFilterChain exampleLambda() {
		return HttpSecurityFilterChain.of((chain) -> {
			chain.sessionManagement((sessionManagement) -> {
				sessionManagement.policy(Policy.USE_EXISTING);
				sessionManagement.concurrency().maximumSessions(10);
				sessionManagement.fixation(Fixation.MIGRATED);
				sessionManagement.enableUrlRewriting();
				sessionManagement.concurrency((concurrency) -> {
					concurrency.maximumSessionsPreventsLogin(true);
					concurrency.expiredStrategy(this.mySessionExpiredStrategy);
				});
			});
		});
	}

}
