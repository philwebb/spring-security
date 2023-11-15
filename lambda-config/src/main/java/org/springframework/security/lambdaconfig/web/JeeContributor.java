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

import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.authentication.preauth.j2ee.J2eePreAuthenticatedProcessingFilter;

/**
 * @author Rob Winch
 * @author Phillip Webb
 */
public class JeeContributor implements SecurityFilterChainContributor<JeeContributor.Configurer> {

	private static final JeeContributor INSTANCE = new JeeContributor();

	public static JeeContributor instance() {
		return INSTANCE;
	}

	private JeeContributor() {
	}

	@Override
	public SecurityFilterChainContribution contribute(SecurityFilterChainContributionContext contributionContext,
			Consumer<Configurer> jee) {
		return SecurityFilterChainContribution.create(JeeContribution::new, contributionContext, jee);
	}

	/**
	 * Callback for configuring a {@link JeeContributor}.
	 */
	public interface Configurer extends SecurityFilterChainContributor.Configurer {

		// @formatter:off
		/* FIXME === DESIGN NOTES ===

		Based on org.springframework.security.config.annotation.web.configurers.
		JeeConfigurer<H>

		- rename jeePreAuthenticatedProcessingFilter to preAuthenticatedProcessingFilter
		- change mappable to addMappable to allow multiple calls. Drop the Set variant

		*/
		// @formatter:on

		void addMappableAuthorities(String... mappableAuthorities);

		void addMappableRoles(String... mappableRoles);

		void authenticatedUserDetailsService(
				AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken> authenticatedUserDetailsService);

		void preAuthenticatedProcessingFilter(J2eePreAuthenticatedProcessingFilter preAuthenticatedProcessingFilter);

	}

}
