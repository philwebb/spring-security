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

/**
 * @author Joe Grandja
 * @author Kazuki Shimizu
 * @author Phillip Webb
 */
public class Oauth2LoginContributor implements SecurityFilterChainContributor<Oauth2LoginContributor.Configurer> {

	private static final Oauth2LoginContributor INSTANCE = new Oauth2LoginContributor();

	public static Oauth2LoginContributor instance() {
		return INSTANCE;
	}

	private Oauth2LoginContributor() {
	}

	@Override
	public SecurityFilterChainContribution contribute(SecurityFilterChainContributionContext contributionContext,
			Consumer<Configurer> oauth2Login) {
		return SecurityFilterChainContribution.create(Oauth2LoginContribution::new, contributionContext, oauth2Login);
	}

	/**
	 * Callback for configuring a {@link Oauth2LoginContributor}.
	 */
	public interface Configurer extends SecurityFilterChainContributor.Configurer {

	}

}
