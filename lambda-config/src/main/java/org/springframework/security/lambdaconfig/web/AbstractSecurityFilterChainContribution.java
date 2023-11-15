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

/**
 * Abstract base class for a typical {@link SecurityFilterChainContribution}.
 *
 * @author Phillip Webb
 */
abstract class AbstractSecurityFilterChainContribution
		implements SecurityFilterChainContribution, SecurityFilterChainContributor.Configurer {

	// FIXME we need to think about package organization. Perhaps for subclasses a package
	// per jar that the thing needs?

	private final SecurityFilterChainContributionContext contributionContext;

	AbstractSecurityFilterChainContribution(SecurityFilterChainContributionContext contributionContext) {
		this.contributionContext = contributionContext;
	}

	protected final SecurityFilterChainContributionContext getContributionContext() {
		return this.contributionContext;
	}

	@Override
	public void disable() {
		this.contributionContext.removeContribution();
	}

}
