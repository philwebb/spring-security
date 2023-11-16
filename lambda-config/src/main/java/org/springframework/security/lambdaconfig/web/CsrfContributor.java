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

import java.util.function.Consumer;

import org.springframework.security.lambdaconfig.web.CsrfContributor.Configurer;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestHandler;

/**
 * @author Phillip Webb
 */
public final class CsrfContributor implements SecurityFilterChainContributor<Configurer> {

	private static final CsrfContributor INSTANCE = new CsrfContributor();

	public static CsrfContributor instance() {
		return INSTANCE;
	}

	private CsrfContributor() {
	}

	@Override
	public SecurityFilterChainContribution contribute(SecurityFilterChainContributionContext contributionContext,
			Consumer<Configurer> csrf) {
		return SecurityFilterChainContribution.create(CsrfContribution::new, contributionContext, csrf);
	}

	public interface Configurer extends SecurityFilterChainContributor.Configurer {

		RequestMatching apply();

		void tokenRepository(CsrfTokenRepository csrfTokenRepository);

		void tokenRequestHandler(CsrfTokenRequestHandler requestHandler);

		void sessionAuthenticationStrategy(SessionAuthenticationStrategy sessionAuthenticationStrategy);

	}

}
