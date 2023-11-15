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

import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestHandler;

/**
 * A {@link SecurityFilterChainContribution} made by the {@link CsrfContributor}.
 *
 * @author Rob Winch
 * @author Michael Vitz
 * @author Phillip Webb
 * @see CsrfContributor
 */
final class CsrfContribution extends AbstractSecurityFilterChainContribution implements CsrfContributor.Configurer {

	CsrfContribution(SecurityFilterChainContributionContext contributionContext) {
		super(contributionContext);
	}

	@Override
	public void tokenRepository(CsrfTokenRepository csrfTokenRepository) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void tokenRequestHandler(CsrfTokenRequestHandler requestHandler) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void sessionAuthenticationStrategy(SessionAuthenticationStrategy sessionAuthenticationStrategy) {
		throw new UnsupportedOperationException();
	}

	@Override
	public RequestMatching apply() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void contribute(SharedObjects sharedObjects, SecurityFilterChainBuilder instance) {
		throw new UnsupportedOperationException();
	}

}
