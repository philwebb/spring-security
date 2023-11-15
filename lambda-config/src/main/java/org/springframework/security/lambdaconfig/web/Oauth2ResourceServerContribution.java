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

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;

/**
 * A {@link SecurityFilterChainContribution} made by the
 * {@link Oauth2ResourceServerContributor}.
 *
 * @author Josh Cummings
 * @author Evgeniy Cheban
 * @author Jerome Wacongne
 * @author Phillip Webb
 * @see Oauth2ResourceServerContributor
 */
final class Oauth2ResourceServerContribution extends AbstractSecurityFilterChainContribution
		implements Oauth2ResourceServerContributor.Configurer {

	Oauth2ResourceServerContribution(SecurityFilterChainContributionContext contributionContext) {
		super(contributionContext);
	}

	@Override
	public void accessDeniedHandler(AccessDeniedHandler accessDeniedHandler) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void authenticationEntryPoint(AuthenticationEntryPoint entryPoint) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void authenticationManagerResolver(
			AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void bearerTokenResolver(BearerTokenResolver bearerTokenResolver) {
		throw new UnsupportedOperationException();
	}

	@Override
	public JwtConfigurer jwt() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void jwt(Consumer<JwtConfigurer> jwtCustomizer) {
		throw new UnsupportedOperationException();
	}

	@Override
	public OpaqueTokenConfigurer opaqueToken() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void opaqueToken(Consumer<OpaqueTokenConfigurer> opaqueTokenCustomizer) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void contribute(SharedObjects sharedObjects, SecurityFilterChainBuilder builder) {
		throw new UnsupportedOperationException();
	}

}
