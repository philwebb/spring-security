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

import org.springframework.security.web.header.HeaderWriter;

/**
 * A {@link SecurityFilterChainContribution} made by the {@link HeadersContributor}.
 *
 * @author Rob Winch
 * @author Tim Ysewyn
 * @author Joe Grandja
 * @author Eddú Meléndez
 * @author Vedran Pavic
 * @author Ankur Pathak
 * @author Daniel Garnier-Moiroux
 * @author Phillip Webb
 * @see HeadersContributor
 */
final class HeadersContribution extends AbstractSecurityFilterChainContribution
		implements HeadersContributor.Configurer {

	HeadersContribution(SecurityFilterChainContributionContext contributionContext) {
		super(contributionContext);
	}

	@Override
	public void disableAll() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void addHeaderWriter(HeaderWriter headerWriter) {
		throw new UnsupportedOperationException();
	}

	@Override
	public ContentTypeOptionsConfigurer contentTypeOptions() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void contentTypeOptions(Consumer<ContentTypeOptionsConfigurer> contentTypeOptions) {
		throw new UnsupportedOperationException();
	}

	@Override
	public XssProtectionConfigurer xssProtection() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void xssProtection(Consumer<XssProtectionConfigurer> xss) {
		throw new UnsupportedOperationException();
	}

	@Override
	public CacheControlConfigurer cacheControl() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void cacheControl(Consumer<CacheControlConfigurer> xss) {
		throw new UnsupportedOperationException();
	}

	@Override
	public HttpStrictTransportSecurityConfigurer httpStrictTransportSecurity() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void httpStrictTransportSecurity(Consumer<HttpStrictTransportSecurityConfigurer> hsts) {
		throw new UnsupportedOperationException();
	}

	@Override
	public FrameOptionsConfigurer frameOptions() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void frameOptions(Consumer<FrameOptionsConfigurer> frameOptions) {
		throw new UnsupportedOperationException();
	}

	@Override
	public ContentSecurityConfigurer contentSecurity() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void contentSecurity(Consumer<ContentSecurityConfigurer> contentSecurityPolicy) {
		throw new UnsupportedOperationException();
	}

	@Override
	public ReferrerConfigurer referrer() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void referrer(Consumer<ReferrerConfigurer> referrerPolicy) {
		throw new UnsupportedOperationException();
	}

	@Override
	public PermissionsConfigurer permissions() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void permissions(Consumer<PermissionsConfigurer> permissionsPolicy) {
		throw new UnsupportedOperationException();
	}

	@Override
	public CrossOriginOpenerConfigurer crossOriginOpener() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void crossOriginOpener(Consumer<CrossOriginOpenerConfigurer> crossOriginOpenerPolicy) {
		throw new UnsupportedOperationException();
	}

	@Override
	public CrossOriginEmbedderConfigurer crossOriginEmbedder() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void crossOriginEmbedder(Consumer<CrossOriginEmbedderConfigurer> crossOriginEmbedderPolicy) {
		throw new UnsupportedOperationException();
	}

	@Override
	public CrossOriginResourceConfigurer crossOriginResource() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void crossOriginResource(Consumer<CrossOriginResourceConfigurer> crossOriginResourcePolicy) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void contribute(SharedObjects sharedObjects, SecurityFilterChainBuilder builder) {
		throw new UnsupportedOperationException();
	}

}
