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

import org.springframework.security.web.SecurityFilterChain;

/**
 * @author Phillip Webb
 */
public interface HttpSecurityFilterChain extends SecurityFilterChain {

	static HttpSecurityFilterChain of(Consumer<Configurer> chain) {
		// create new thing
		// addDefaults();
		// chain.accept(thing)
		// thing.createChain
		return null;
	}

	static HttpSecurityFilterChain empty(Consumer<Configurer> chain) {
		return null;
	}

	interface Configurer {

		// FIXME can we group some of these. Oauth ? Saml

		RequestMatching apply();

		default void headers(Consumer<Headers.Configurer> authorizations) {
			customize(Headers.instance(), authorizations);
		}

		default void cors(Consumer<Cors.Configurer> authorizations) {
			customize(Cors.instance(), authorizations);
		}

		default void sessionManagement(Consumer<SessionManagement.Configurer> authorizations) {
			customize(SessionManagement.instance(), authorizations);
		}

		default void portMapper(Consumer<PortMapper.Configurer> authorizations) {
			customize(PortMapper.instance(), authorizations);
		}

		default void jee(Consumer<Jee.Configurer> authorizations) {
			customize(Jee.instance(), authorizations);
		}

		default void x509(Consumer<X509.Configurer> authorizations) {
			customize(X509.instance(), authorizations);
		}

		default void rememberMe(Consumer<RememberMe.Configurer> authorizations) {
			customize(RememberMe.instance(), authorizations);
		}

		default void authorizeRequests(Consumer<AuthorizeRequests.Configurer> authorizations) {
			customize(AuthorizeRequests.instance(), authorizations);
		}

		default void authorizeRequestsForServletPath(String servletPath,
				Consumer<AuthorizeRequests.Configurer> servletAuthorizations) {
			authorizeRequests((authorizations) -> authorizations.forServletPath(servletPath, servletAuthorizations));
		}

		default void requestCache(Consumer<RequestCache.Configurer> authorizations) {
			customize(RequestCache.instance(), authorizations);
		}

		default void exceptionHandling(Consumer<ExceptionHandling.Configurer> authorizations) {
			customize(ExceptionHandling.instance(), authorizations);
		}

		default void securityContext(Consumer<SecurityContext.Configurer> authorizations) {
			customize(SecurityContext.instance(), authorizations);
		}

		default void servletApi(Consumer<ServletApi.Configurer> authorizations) {
			customize(ServletApi.instance(), authorizations);
		}

		default void csrf(Consumer<Csrf.Configurer> csrf) {
			customize(Csrf.instance(), csrf);
		}

		default void logout(Consumer<Logout.Configurer> authorizations) {
			customize(Logout.instance(), authorizations);
		}

		default void anonymous(Consumer<Anonymous.Configurer> authorizations) {
			customize(Anonymous.instance(), authorizations);
		}

		default void formLogin(Consumer<FormLogin.Configurer> authorizations) {
			customize(FormLogin.instance(), authorizations);
		}

		default void saml2Login(Consumer<Saml2Login.Configurer> authorizations) {
			customize(Saml2Login.instance(), authorizations);
		}

		default void saml2Logout(Consumer<Saml2Logout.Configurer> authorizations) {
			customize(Saml2Logout.instance(), authorizations);
		}

		default void saml2Metadata(Consumer<Saml2Metadata.Configurer> authorizations) {
			customize(Saml2Metadata.instance(), authorizations);
		}

		default void oauth2Login(Consumer<Oauth2Login.Configurer> authorizations) {
			customize(Oauth2Login.instance(), authorizations);
		}

		default void oidcLogout(Consumer<OidcLogout.Configurer> authorizations) {
			customize(OidcLogout.instance(), authorizations);
		}

		default void oauth2Client(Consumer<Oauth2Client.Configurer> authorizations) {
			customize(Oauth2Client.instance(), authorizations);
		}

		default void oauth2ResourceServer(Consumer<Oauth2ResourceServer.Configurer> authorizations) {
			customize(Oauth2ResourceServer.instance(), authorizations);
		}

		default void requiresChannel(Consumer<RequiresChannel.Configurer> authorizations) {
			customize(RequiresChannel.instance(), authorizations);
		}

		default void httpBasic(Consumer<HttpBasic.Configurer> authorizations) {
			customize(HttpBasic.instance(), authorizations);
		}

		default void passwordManagement(Consumer<PasswordManagement.Configurer> authorizations) {
			customize(PasswordManagement.instance(), authorizations);
		}

		<C> void customize(SecurityFilterChainContributor<C> contributor, Consumer<C> cutomizer);

	}

}
