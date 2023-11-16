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

package org.springframework.security.lambdaconfig.web2;

import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestHandler;
import org.springframework.security.web.util.matcher.RequestMatcher;

final class CsrfContribution implements Csrf.Configurer, SecurityContribution<SecurityFilterChainBuilder> {

	private final ContributionContext contributionContext;

	CsrfContribution(ContributionContext contributionContext) {
		this.contributionContext = contributionContext;
	}

	@Override
	public void apply(SharedObjects sharedObjects, SecurityFilterChainBuilder instance) {
		throw new UnsupportedOperationException("Auto-generated method stub");
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see
	 * org.springframework.security.lambdaconfig.web2.Csrf.Configurer#csrfTokenRepository(
	 * org.springframework.security.web.csrf.CsrfTokenRepository)
	 */
	@Override
	public void setTokenRepository(CsrfTokenRepository csrfTokenRepository) {
		// TODO Auto-generated method stub
		throw new UnsupportedOperationException("Auto-generated method stub");
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see org.springframework.security.lambdaconfig.web2.Csrf.Configurer#
	 * requireCsrfProtectionMatcher(org.springframework.security.web.util.matcher.
	 * RequestMatcher)
	 */
	@Override
	public void setRequireFor(RequestMatcher requireCsrfProtectionMatcher) {
		// TODO Auto-generated method stub
		throw new UnsupportedOperationException("Auto-generated method stub");
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see org.springframework.security.lambdaconfig.web2.Csrf.Configurer#
	 * csrfTokenRequestHandler(org.springframework.security.web.csrf.
	 * CsrfTokenRequestHandler)
	 */
	@Override
	public void tokenRequestHandler(CsrfTokenRequestHandler requestHandler) {
		// TODO Auto-generated method stub
		throw new UnsupportedOperationException("Auto-generated method stub");
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see org.springframework.security.lambdaconfig.web2.Csrf.Configurer#
	 * ignoringRequestMatchers(org.springframework.security.web.util.matcher.
	 * RequestMatcher[])
	 */
	@Override
	public void ignore(RequestMatcher... requestMatchers) {
		// TODO Auto-generated method stub
		throw new UnsupportedOperationException("Auto-generated method stub");
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see org.springframework.security.lambdaconfig.web2.Csrf.Configurer#
	 * ignoringRequestMatchers(java.lang.String[])
	 */
	@Override
	public void ignore(String... patterns) {
		// TODO Auto-generated method stub
		throw new UnsupportedOperationException("Auto-generated method stub");
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see org.springframework.security.lambdaconfig.web2.Csrf.Configurer#
	 * sessionAuthenticationStrategy(org.springframework.security.web.authentication.
	 * session.SessionAuthenticationStrategy)
	 */
	@Override
	public void sessionAuthenticationStrategy(SessionAuthenticationStrategy sessionAuthenticationStrategy) {
		// TODO Auto-generated method stub
		throw new UnsupportedOperationException("Auto-generated method stub");
	}

	@Override
	public void disable() {
		this.contributionContext.removeContribution();
	}

}
