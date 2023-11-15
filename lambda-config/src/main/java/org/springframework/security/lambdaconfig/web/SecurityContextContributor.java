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

import org.springframework.security.web.context.SecurityContextRepository;

/**
 * @author Rob Winch
 * @author Phillip Webb
 */
public class SecurityContextContributor
		implements SecurityFilterChainContributor<SecurityContextContributor.Configurer> {

	private static final SecurityContextContributor INSTANCE = new SecurityContextContributor();

	public static SecurityContextContributor instance() {
		return INSTANCE;
	}

	private SecurityContextContributor() {
	}

	@Override
	public SecurityFilterChainContribution contribute(SecurityFilterChainContributionContext contributionContext,
			Consumer<Configurer> securityContext) {
		return SecurityFilterChainContribution.create(SecurityContextContribution::new, contributionContext,
				securityContext);
	}

	/**
	 * Callback for configuring a {@link SecurityContextContributor}.
	 */
	public interface Configurer extends SecurityFilterChainContributor.Configurer {

		// @formatter:off
		/* FIXME === DESIGN NOTES ===

		org.springframework.security.config.annotation.web.configurers.
		SecurityContextConfigurer<H>

		- rename securityContextRepository to repository

		*/
		// @formatter:on

		void repository(SecurityContextRepository securityContextRepository);

		void requireExplicitSave(boolean requireExplicitSave);

	}

}
