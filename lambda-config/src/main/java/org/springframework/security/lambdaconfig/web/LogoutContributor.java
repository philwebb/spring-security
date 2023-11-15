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

import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

/**
 * @author Rob Winch
 * @author Onur Kagan Ozcan
 */
public class LogoutContributor implements SecurityFilterChainContributor<LogoutContributor.Configurer> {

	private static final LogoutContributor INSTANCE = new LogoutContributor();

	public static LogoutContributor instance() {
		return INSTANCE;
	}

	private LogoutContributor() {
	}

	@Override
	public SecurityFilterChainContribution contribute(SecurityFilterChainContributionContext contributionContext,
			Consumer<Configurer> logout) {
		return SecurityFilterChainContribution.create(LogoutContribution::new, contributionContext, logout);
	}

	/**
	 * Callback for configuring a {@link LogoutContributor}.
	 */
	public interface Configurer extends SecurityFilterChainContributor.Configurer {

		// @formatter:off
		/* FIXME === DESIGN NOTES ===

		Based on org.springframework.security.config.annotation.web.configurers.
		LogoutConfigurer<H>

		- permitAll renamed to permitRequests and boolean version dropped. We can probably get away without it since just drop the permit call
		- logoutUrl renamed to url
		- logoutSuccessUrl renamed to successUrl (to align with AuthenticationConfigurer)
		- logoutRequestMatcher changed to apply
		- deleteCookies rename to addClearedCookies since it can be called multiple times
		- defaultLogoutSuccessHandlerFor and logoutSuccessHandler replaced with addSuccessHandler
		- defaultSuccessHandler added (similar pattern to ExceptionHandlingContributor)

		*/
		// @formatter:on

		void addLogoutHandler(LogoutHandler logoutHandler);

		void clearAuthentication(boolean clearAuthentication);

		void invalidateHttpSession(boolean invalidateHttpSession);

		void url(String logoutUrl);

		RequestMatching apply();

		void successUrl(String logoutSuccessUrl);

		void permitRequests();

		void addClearedCookies(String... cookieNamesToClear);

		RequestMatching addSuccessHandler(LogoutSuccessHandler successHandler);

		void defaultSuccessHandler(LogoutSuccessHandler successHandler);

	}

}
