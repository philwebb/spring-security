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
 * @author Rob Winch
 * @author Phillip Webb
 */
public class X509Contributor implements SecurityFilterChainContributor<X509Contributor.Configurer> {

	private static final X509Contributor INSTANCE = new X509Contributor();

	public static X509Contributor instance() {
		return INSTANCE;
	}

	private X509Contributor() {
	}

	@Override
	public SecurityFilterChainContribution contribute(SecurityFilterChainContributionContext contributionContext,
			Consumer<Configurer> csrf) {
		return null;
	}

	/**
	 * Callback for configuring a {@link X509Contributor}.
	 */
	public interface Configurer extends SecurityFilterChainContributor.Configurer {

	}

}
