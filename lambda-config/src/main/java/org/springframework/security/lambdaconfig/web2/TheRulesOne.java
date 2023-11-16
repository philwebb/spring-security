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

package org.springframework.security.lambdaconfig.web2;

/**
 * @author pwebb
 *
 * org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer.AuthorizationManagerRequestMatcherRegistry
 *
 */
public interface TheRulesOne {

	/*
	 * public AuthorizationManagerRequestMatcherRegistry forServletPattern(String pattern,
	 * Customizer<AuthorizationManagerServletRequestMatcherRegistry> customizer);
	 *
	 * withObjectPostProcessor
	 *
	 *
	 */

	/*
	 * AbstractRequestMatcherBuilderRegistry (C is AuthorizedUrl)
	 *
	 * public final C requestMatchers(String... patterns) {
	 *
	 * public final C requestMatchers(HttpMethod method, String... patterns) {
	 *
	 * public final C requestMatchers(HttpMethod method) {
	 *
	 * AbstractRequestMatcherRegistry
	 *
	 * public C anyRequest() {
	 *
	 * public C dispatcherTypeMatchers(@Nullable HttpMethod method, DispatcherType...
	 * dispatcherTypes) {
	 *
	 * public C dispatcherTypeMatchers(DispatcherType... dispatcherTypes) {
	 *
	 * public C requestMatchers(RequestMatcher... requestMatchers) {
	 *
	 * public C requestMatchers(HttpMethod method, String... patterns) {
	 *
	 * public C requestMatchers(String... patterns) {
	 *
	 * public C requestMatchers(HttpMethod method) {
	 *
	 */

	/*
	 * AuthorizedUrl
	 *
	 * permitAll()
	 *
	 * denyAll()
	 *
	 * hasRole()
	 *
	 * hasAnyRole()
	 *
	 * hasAuthority
	 *
	 * hasAnyAuthority
	 *
	 * authenticated
	 *
	 * fullyAuthenticated
	 *
	 * rememberMe
	 *
	 * anonymous
	 *
	 * access
	 */

	// Matchers and Manager
	// AuthorizationManager / RequestMatcher

}
