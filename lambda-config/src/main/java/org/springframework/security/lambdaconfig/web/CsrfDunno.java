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

import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestHandler;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * @author pwebb
 */
class CsrfDunno implements ConfigurerInstance<Csrf>, Csrf {

	@Override
	public void csrfTokenRepository(CsrfTokenRepository csrfTokenRepository) {
		// update state
	}

	@Override
	public void requireCsrfProtectionMatcher(RequestMatcher requireCsrfProtectionMatcher) {
		// update state
	}

	@Override
	public void csrfTokenRequestHandler(CsrfTokenRequestHandler requestHandler) {
		// update state
	}

	@Override
	public void ignoringRequestMatchers(RequestMatcher... requestMatchers) {
		// update state
	}

	@Override
	public void ignoringRequestMatchers(String... patterns) {
		// update state
	}

	@Override
	public void sessionAuthenticationStrategy(SessionAuthenticationStrategy sessionAuthenticationStrategy) {
		// update state
	}

	@Override
	public void customize(Consumer<Csrf> configurer) {
		configurer.accept(this);
	}

	@Override
	public void applyTo(DunnoBuilder to) {
		// shared object etc
		// add filter etc
	}

}
