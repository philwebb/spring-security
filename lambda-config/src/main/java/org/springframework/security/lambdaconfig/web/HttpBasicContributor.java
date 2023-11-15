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

import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.context.SecurityContextRepository;

/**
 * @author Rob Winch
 * @author Evgeniy Cheban
 * @author Phillip Webb
 */
public class HttpBasicContributor implements SecurityFilterChainContributor<HttpBasicContributor.Configurer> {

	private static final HttpBasicContributor INSTANCE = new HttpBasicContributor();

	public static HttpBasicContributor instance() {
		return INSTANCE;
	}

	private HttpBasicContributor() {
	}

	@Override
	public SecurityFilterChainContribution contribute(SecurityFilterChainContributionContext contributionContext,
			Consumer<Configurer> httpBasic) {
		return SecurityFilterChainContribution.create(HttpBasicContribution::new, contributionContext, httpBasic);
	}

	/**
	 * Callback for configuring a {@link HttpBasicContributor}.
	 */
	public interface Configurer extends SecurityFilterChainContributor.Configurer {

		// @formatter:off
		/* FIXME === DESIGN NOTES ===

		Based on org.springframework.security.config.annotation.web.configurers.
		HttpBasicConfigurer<B>

		- authenticationEntryPoint logic looks similar to ExceptionHandlingContributor
		  but that one allows multiple. Should we have the same?

		*/
		// @formatter:on

		void realmName(String realmName);

		void authenticationEntryPoint(AuthenticationEntryPoint authenticationEntryPoint);

		void authenticationDetailsSource(
				AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource);

		void securityContextRepository(SecurityContextRepository securityContextRepository);

	}

}
