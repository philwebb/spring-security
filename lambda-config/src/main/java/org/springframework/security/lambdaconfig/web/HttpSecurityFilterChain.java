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
		throw new UnsupportedOperationException();
	}

	/**
	 * Callback for configuring a {@link HttpSecurityFilterChain}.
	 */
	interface Configurer {

		/**
		 * Disable all configuration contributions and start with an empty chain.
		 */
		void disableAll();

		/**
		 * Configure when the {@link HttpSecurityFilterChain} should be applied.
		 * @return a {@link RequestMatching} instance that can be used to configure when
		 * the chain is applied
		 */
		RequestMatching apply();

		/**
		 * Add or update {@link HeadersContributor security headers} configuration for the
		 * chain.
		 * @return a configurer to apply the configuration
		 */
		default HeadersContributor.Configurer headers() {
			return configure(HeadersContributor.instance());
		}

		/**
		 * Add or update {@link HeadersContributor security headers} configuration for the
		 * chain.
		 * @param headers the callback used to apply the configuration
		 */
		default void headers(Consumer<HeadersContributor.Configurer> headers) {
			configure(HeadersContributor.instance(), headers);
		}

		/**
		 * Add or update {@link CorsContributor CORS (Cross-origin resource sharing)}
		 * configuration for the chain.
		 * @return a configurer to apply the configuration
		 */
		default CorsContributor.Configurer cors() {
			return configure(CorsContributor.instance());
		}

		/**
		 * Add or update {@link CorsContributor CORS (Cross-origin resource sharing)}
		 * configuration for the chain.
		 * @param cors the callback used to apply the configuration
		 */
		default void cors(Consumer<CorsContributor.Configurer> cors) {
			configure(CorsContributor.instance(), cors);
		}

		/**
		 * Add or update {@link SessionManagementContributor session management}
		 * configuration for the chain.
		 * @return a configurer to apply the configuration
		 */
		default SessionManagementContributor.Configurer sessionManagement() {
			return configure(SessionManagementContributor.instance());
		}

		/**
		 * Add or update {@link SessionManagementContributor session management}
		 * configuration for the chain.
		 * @param sessionManagement the callback used to apply the configuration
		 */
		default void sessionManagement(Consumer<SessionManagementContributor.Configurer> sessionManagement) {
			configure(SessionManagementContributor.instance(), sessionManagement);
		}

		/**
		 * Add or update {@link PortMapperContributor port mapper} configuration for the
		 * chain.
		 * @return a configurer to apply the configuration
		 */
		default PortMapperContributor.Configurer portMapper() {
			return configure(PortMapperContributor.instance());
		}

		/**
		 * Add or update {@link PortMapperContributor port mapper} configuration for the
		 * chain.
		 * @param portMapper the callback used to apply the configuration
		 */
		default void portMapper(Consumer<PortMapperContributor.Configurer> portMapper) {
			configure(PortMapperContributor.instance(), portMapper);
		}

		/**
		 * Add or update {@link JeeContributor JEE} configuration for the chain.
		 * @return a configurer to apply the configuration
		 */
		default JeeContributor.Configurer jee() {
			return configure(JeeContributor.instance());
		}

		/**
		 * Add or update {@link JeeContributor JEE} configuration for the chain.
		 * @param jee the callback used to apply the configuration
		 */
		default void jee(Consumer<JeeContributor.Configurer> jee) {
			configure(JeeContributor.instance(), jee);
		}

		/**
		 * Add or update {@link X509Contributor X509} configuration for the chain.
		 * @return a configurer to apply the configuration
		 */
		default X509Contributor.Configurer x509() {
			return configure(X509Contributor.instance());
		}

		/**
		 * Add or update {@link X509Contributor X509} configuration for the chain.
		 * @param x509 the callback used to apply the configuration
		 */
		default void x509(Consumer<X509Contributor.Configurer> x509) {
			configure(X509Contributor.instance(), x509);
		}

		/**
		 * Add or update {@link RememberMeContributor "remember me"} configuration for the
		 * chain.
		 * @return a configurer to apply the configuration
		 */
		default RememberMeContributor.Configurer rememberMe() {
			return configure(RememberMeContributor.instance());
		}

		/**
		 * Add or update {@link RememberMeContributor "remember me"} configuration for the
		 * chain.
		 * @param rememberMe the callback used to apply the configuration
		 */
		default void rememberMe(Consumer<RememberMeContributor.Configurer> rememberMe) {
			configure(RememberMeContributor.instance(), rememberMe);
		}

		/**
		 * Add or update {@link AuthorizeRequestsContributor authorize requests}
		 * configuration for the chain.
		 * @return a configurer to apply the configuration
		 */
		default AuthorizeRequestsContributor.Configurer authorizeRequests() {
			return configure(AuthorizeRequestsContributor.instance());
		}

		/**
		 * Add or update {@link AuthorizeRequestsContributor authorize requests}
		 * configuration for the chain.
		 * @param authorizeRequests the callback used to apply the configuration
		 */
		default void authorizeRequests(Consumer<AuthorizeRequestsContributor.Configurer> authorizeRequests) {
			configure(AuthorizeRequestsContributor.instance(), authorizeRequests);
		}

		/**
		 * Add or update {@link RequestCacheContributor request cache} configuration for
		 * the chain.
		 * @return a configurer to apply the configuration
		 */
		default RequestCacheContributor.Configurer requestCache() {
			return configure(RequestCacheContributor.instance());
		}

		/**
		 * Add or update {@link RequestCacheContributor request cache} configuration for
		 * the chain.
		 * @param requestCache the callback used to apply the configuration
		 */
		default void requestCache(Consumer<RequestCacheContributor.Configurer> requestCache) {
			configure(RequestCacheContributor.instance(), requestCache);
		}

		/**
		 * Add or update {@link ExceptionHandlingContributor exception handling}
		 * configuration for the chain.
		 * @return a configurer to apply the configuration
		 */
		default ExceptionHandlingContributor.Configurer exceptionHandling() {
			return configure(ExceptionHandlingContributor.instance());
		}

		/**
		 * Add or update {@link ExceptionHandlingContributor exception handling}
		 * configuration for the chain.
		 * @param exceptionHandling the callback used to apply the configuration
		 */
		default void exceptionHandling(Consumer<ExceptionHandlingContributor.Configurer> exceptionHandling) {
			configure(ExceptionHandlingContributor.instance(), exceptionHandling);
		}

		/**
		 * Add or update {@link SecurityContextContributor security context} configuration
		 * for the chain.
		 * @return a configurer to apply the configuration
		 */
		default SecurityContextContributor.Configurer securityContext() {
			return configure(SecurityContextContributor.instance());
		}

		/**
		 * Add or update {@link SecurityContextContributor security context} configuration
		 * for the chain.
		 * @param securityContext the callback used to apply the configuration
		 */
		default void securityContext(Consumer<SecurityContextContributor.Configurer> securityContext) {
			configure(SecurityContextContributor.instance(), securityContext);
		}

		/**
		 * Add or update {@link ServletApiContributor servlet API} configuration for the
		 * chain.
		 * @return a configurer to apply the configuration
		 */
		default ServletApiContributor.Configurer servletApi() {
			return configure(ServletApiContributor.instance());
		}

		/**
		 * Add or update {@link ServletApiContributor servlet API} configuration for the
		 * chain.
		 * @param servletApi the callback used to apply the configuration
		 */
		default void servletApi(Consumer<ServletApiContributor.Configurer> servletApi) {
			configure(ServletApiContributor.instance(), servletApi);
		}

		/**
		 * Add or update {@link CsrfContributor CSRF (Cross-Site Request Forgery)}
		 * configuration for the chain.
		 * @return a configurer to apply the configuration
		 */
		default CsrfContributor.Configurer csrf() {
			return configure(CsrfContributor.instance());
		}

		/**
		 * Add or update {@link CsrfContributor CSRF (Cross-Site Request Forgery)}
		 * configuration for the chain.
		 * @param csrf the callback used to apply the configuration
		 */
		default void csrf(Consumer<CsrfContributor.Configurer> csrf) {
			configure(CsrfContributor.instance(), csrf);
		}

		/**
		 * Add or update {@link LogoutContributor logout} configuration for the chain.
		 * @return a configurer to apply the configuration
		 */
		default LogoutContributor.Configurer logout() {
			return configure(LogoutContributor.instance());
		}

		/**
		 * Add or update {@link LogoutContributor logout} configuration for the chain.
		 * @param logout the callback used to apply the configuration
		 */
		default void logout(Consumer<LogoutContributor.Configurer> logout) {
			configure(LogoutContributor.instance(), logout);
		}

		/**
		 * Add or update {@link AnonymousContributor anonymous} configuration for the
		 * chain.
		 * @return a configurer to apply the configuration
		 */
		default AnonymousContributor.Configurer anonymous() {
			return configure(AnonymousContributor.instance());
		}

		/**
		 * Add or update {@link AnonymousContributor anonymous} configuration for the
		 * chain.
		 * @param anonymous the callback used to apply the configuration
		 */
		default void anonymous(Consumer<AnonymousContributor.Configurer> anonymous) {
			configure(AnonymousContributor.instance(), anonymous);
		}

		/**
		 * Add or update {@link FormLoginContributor form login} configuration for the
		 * chain.
		 * @return a configurer to apply the configuration
		 */
		default FormLoginContributor.Configurer formLogin() {
			return configure(FormLoginContributor.instance());
		}

		/**
		 * Add or update {@link FormLoginContributor form login} configuration for the
		 * chain.
		 * @param formLogin the callback used to apply the configuration
		 */
		default void formLogin(Consumer<FormLoginContributor.Configurer> formLogin) {
			configure(FormLoginContributor.instance(), formLogin);
		}

		/**
		 * Add or update {@link Saml2LoginContributor SAML 2.0 (Security Assertion Markup
		 * Language) login} configuration for the chain.
		 * @return a configurer to apply the configuration
		 */
		default Saml2LoginContributor.Configurer saml2Login() {
			return configure(Saml2LoginContributor.instance());
		}

		/**
		 * Add or update {@link Saml2LoginContributor SAML 2.0 (Security Assertion Markup
		 * Language) login} configuration for the chain.
		 * @param saml2Login the callback used to apply the configuration
		 */
		default void saml2Login(Consumer<Saml2LoginContributor.Configurer> saml2Login) {
			configure(Saml2LoginContributor.instance(), saml2Login);
		}

		/**
		 * Add or update {@link Saml2LogoutContributor SAML 2.0 (Security Assertion Markup
		 * Language) logout} configuration for the chain.
		 * @return a configurer to apply the configuration
		 */
		default Saml2LogoutContributor.Configurer saml2Logout() {
			return configure(Saml2LogoutContributor.instance());
		}

		/**
		 * Add or update {@link Saml2LogoutContributor SAML 2.0 (Security Assertion Markup
		 * Language) logout} configuration for the chain.
		 * @param saml2Logout the callback used to apply the configuration
		 */
		default void saml2Logout(Consumer<Saml2LogoutContributor.Configurer> saml2Logout) {
			configure(Saml2LogoutContributor.instance(), saml2Logout);
		}

		/**
		 * Add or update {@link Saml2MetadataContributor SAML 2.0 (Security Assertion
		 * Markup Language) metadata} configuration for the chain.
		 * @return a configurer to apply the configuration
		 */
		default Saml2MetadataContributor.Configurer saml2Metadata() {
			return configure(Saml2MetadataContributor.instance());
		}

		/**
		 * Add or update {@link Saml2MetadataContributor SAML 2.0 (Security Assertion
		 * Markup Language) metadata} configuration for the chain.
		 * @param saml2Metadata the callback used to apply the configuration
		 */
		default void saml2Metadata(Consumer<Saml2MetadataContributor.Configurer> saml2Metadata) {
			configure(Saml2MetadataContributor.instance(), saml2Metadata);
		}

		/**
		 * Add or update {@link Oauth2LoginContributor OAuth 2.0 (Open Authorization)
		 * login} configuration for the chain.
		 * @return a configurer to apply the configuration
		 */
		default Oauth2LoginContributor.Configurer oauth2Login() {
			return configure(Oauth2LoginContributor.instance());
		}

		/**
		 * Add or update {@link Oauth2LoginContributor OAuth 2.0 (Open Authorization)
		 * login} configuration for the chain.
		 * @param oauth2Login the callback used to apply the configuration
		 */
		default void oauth2Login(Consumer<Oauth2LoginContributor.Configurer> oauth2Login) {
			configure(Oauth2LoginContributor.instance(), oauth2Login);
		}

		/**
		 * Add or update {@link OidcLogoutContributor OICD (OpenID Connect) logout}
		 * configuration for the chain.
		 * @return a configurer to apply the configuration
		 */
		default OidcLogoutContributor.Configurer oidcLogout() {
			return configure(OidcLogoutContributor.instance());
		}

		/**
		 * Add or update {@link OidcLogoutContributor OICD (OpenID Connect) logout}
		 * configuration for the chain.
		 * @param oidcLogout the callback used to apply the configuration
		 */
		default void oidcLogout(Consumer<OidcLogoutContributor.Configurer> oidcLogout) {
			configure(OidcLogoutContributor.instance(), oidcLogout);
		}

		/**
		 * Add or update {@link Oauth2ClientContributor OAuth 2.0 (Open Authorization)
		 * client} configuration for the chain.
		 * @return a configurer to apply the configuration
		 */
		default Oauth2ClientContributor.Configurer oauth2Client() {
			return configure(Oauth2ClientContributor.instance());
		}

		/**
		 * Add or update {@link Oauth2ClientContributor OAuth 2.0 (Open Authorization)
		 * client} configuration for the chain.
		 * @param oauth2Client the callback used to apply the configuration
		 */
		default void oauth2Client(Consumer<Oauth2ClientContributor.Configurer> oauth2Client) {
			configure(Oauth2ClientContributor.instance(), oauth2Client);
		}

		/**
		 * Add or update {@link Oauth2ResourceServerContributor OAuth 2.0 (Open
		 * Authorization) resource server} configuration for the chain.
		 * @return a configurer to apply the configuration
		 */
		default Oauth2ResourceServerContributor.Configurer oauth2ResourceServer() {
			return configure(Oauth2ResourceServerContributor.instance());
		}

		/**
		 * Add or update {@link Oauth2ResourceServerContributor OAuth 2.0 (Open
		 * Authorization) resource server} configuration for the chain.
		 * @param oauth2ResourceServer the callback used to apply the configuration
		 */
		default void oauth2ResourceServer(Consumer<Oauth2ResourceServerContributor.Configurer> oauth2ResourceServer) {
			configure(Oauth2ResourceServerContributor.instance(), oauth2ResourceServer);
		}

		/**
		 * Add or update {@link RequiresChannelContributor "requires channel"}
		 * configuration for the chain.
		 * @return a configurer to apply the configuration
		 */
		default RequiresChannelContributor.Configurer requiresChannel() {
			return configure(RequiresChannelContributor.instance());
		}

		/**
		 * Add or update {@link RequiresChannelContributor "requires channel"}
		 * configuration for the chain.
		 * @param requiresChannel the callback used to apply the configuration
		 */
		default void requiresChannel(Consumer<RequiresChannelContributor.Configurer> requiresChannel) {
			configure(RequiresChannelContributor.instance(), requiresChannel);
		}

		/**
		 * Add or update {@link HttpBasicContributor HTTP Basic} configuration for the
		 * chain.
		 * @return a configurer to apply the configuration
		 */
		default HttpBasicContributor.Configurer httpBasic() {
			return configure(HttpBasicContributor.instance());
		}

		/**
		 * Add or update {@link HttpBasicContributor HTTP Basic} configuration for the
		 * chain.
		 * @param httpBasic the callback used to apply the configuration
		 */
		default void httpBasic(Consumer<HttpBasicContributor.Configurer> httpBasic) {
			configure(HttpBasicContributor.instance(), httpBasic);
		}

		/**
		 * Add or update {@link PasswordManagementContributor password management}
		 * configuration for the chain.
		 * @return a configurer to apply the configuration
		 */
		default PasswordManagementContributor.Configurer passwordManagement() {
			return configure(PasswordManagementContributor.instance());
		}

		/**
		 * Add or update {@link PasswordManagementContributor password management}
		 * configuration for the chain.
		 * @param passwordManagement the callback used to apply the configuration
		 */
		default void passwordManagement(Consumer<PasswordManagementContributor.Configurer> passwordManagement) {
			configure(PasswordManagementContributor.instance(), passwordManagement);
		}

		/**
		 * Add or update {@link SecurityFilterChainContributor contributed} configuration
		 * for the chain.
		 * @param <C> the type of configurer
		 * @param contributor the contributor to configure and possibly add
		 * @return a configurer to apply the configuration
		 */
		<C> C configure(SecurityFilterChainContributor<C> contributor);

		/**
		 * Add or update {@link SecurityFilterChainContributor contributed} configuration
		 * for the chain.
		 * @param <C> the type of configurer
		 * @param contributor the contributor to configure and possibly add
		 * @param cutomizer the callback used to apply the configuration
		 */
		<C> void configure(SecurityFilterChainContributor<C> contributor, Consumer<C> cutomizer);

	}

}
