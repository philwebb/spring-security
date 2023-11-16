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
 * A {@link SecurityFilterChainContribution} made by the {@link Saml2LogoutContributor}.
 *
 * @author Josh Cummings
 * @author Phillip Webb
 * @see Saml2LogoutContributor
 */
final class Saml2LogoutContribution extends AbstractSecurityFilterChainContribution
		implements Saml2LogoutContributor.Configurer {

	Saml2LogoutContribution(SecurityFilterChainContributionContext contributionContext) {
		super(contributionContext);
	}

	@Override
	public void contribute(SharedObjects sharedObjects, SecurityFilterChainBuilder builder) {
	}

}
