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
 * A {@link SecurityFilterChainContribution} made by the {@link FormLoginContributor}.
 *
 * @author Rob Winch
 * @author Shazin Sadakath
 * @author Phillip Webb
 * @see FormLoginContributor
 */
final class FormLoginContribution extends AbstractAuthenticationSecurityFilterChainContribution
		implements FormLoginContributor.Configurer {

	FormLoginContribution(SecurityFilterChainContributionContext contributionContext) {
		super(contributionContext);
	}

	@Override
	public void page(String page) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void usernameParameter(String usernameParameter) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void passwordParameter(String passwordParameter) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void contribute(SharedObjects sharedObjects, SecurityFilterChainBuilder builder) {
		throw new UnsupportedOperationException();
	}

}
