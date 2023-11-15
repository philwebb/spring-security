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

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.context.SecurityContextRepository;

/**
 * @author Rob Winch
 * @author Phillip Webb
 */
public interface LoginConfigurer {

	// @formatter:off
	/* FIXME === DESIGN NOTES ===

	Based on org.springframework.security.config.annotation.web.configurers.
	AbstractAuthenticationFilterConfigurer.

	permitAll renamed to permitRequests and boolean version dropped. We can probably get away without it since just drop the permit call

	defaultSuccessUrl renamed to successUrl to align with failureUrl.
	We could make successUrl and successHandler mutually exclusive and fail hard if both are set
	We could make failureUrl and failureHandler mutually exclusive and fail hard if both are set

	*/
	// @formatter:on

	void successUrl(String successUrl);

	void successUrl(String successUrl, boolean alwaysUse);

	void successHandler(AuthenticationSuccessHandler successHandler);

	void processingUrl(String loginProcessingUrl);

	void securityContextRepository(SecurityContextRepository securityContextRepository);

	void authenticationDetailsSource(AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource);

	void failureUrl(String failureUrl);

	void failureHandler(AuthenticationFailureHandler authenticationFailureHandler);

	void permitRequests();

}
