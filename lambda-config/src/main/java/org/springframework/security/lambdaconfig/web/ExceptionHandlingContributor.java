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

import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;

/**
 * @author Rob Winch
 * @author Phillip Webb
 */
public class ExceptionHandlingContributor
		implements SecurityFilterChainContributor<ExceptionHandlingContributor.Configurer> {

	private static final ExceptionHandlingContributor INSTANCE = new ExceptionHandlingContributor();

	public static ExceptionHandlingContributor instance() {
		return INSTANCE;
	}

	private ExceptionHandlingContributor() {
	}

	@Override
	public SecurityFilterChainContribution contribute(SecurityFilterChainContributionContext contributionContext,
			Consumer<Configurer> exceptionHandling) {
		return SecurityFilterChainContribution.create(ExceptionHandlingContribution::new, contributionContext,
				exceptionHandling);
	}

	/**
	 * Callback for configuring a {@link ExceptionHandlingContributor}.
	 */
	public interface Configurer extends SecurityFilterChainContributor.Configurer {

		// FIXME Design note: based on
		// org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer<H>

		// void accessDeniedErrorPage(String accessDeniedUrl);
		// void accessDeniedHandler(AccessDeniedHandler accessDeniedHandler);
		// void defaultAccessDeniedHandlerFor(AccessDeniedHandler deniedHandler,
		// RequestMatcher preferredMatcher);
		// void authenticationEntryPoint(AuthenticationEntryPoint
		// authenticationEntryPoint);
		// void defaultAuthenticationEntryPointFor(AuthenticationEntryPoint entryPoint,
		// RequestMatcher preferredMatcher);

		// The original had quite a bit of logic. If you call accessDeniedHandler
		// that one gets used always. If you call defaultAccessDeniedHandlerFor
		// just once, that one is used and the matcher is used. If you call it
		// more than one then the request matcher is consulted.

		// Same sort of setup with the authenticationEntryPoint.

		RequestMatching addAccessDeniedHandler(AccessDeniedHandler handler);

		RequestMatching addAuthenticationEntryPoint(AuthenticationEntryPoint entryPoint);

	}

}
