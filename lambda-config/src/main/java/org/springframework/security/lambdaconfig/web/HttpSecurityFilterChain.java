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

import java.util.List;
import java.util.function.Consumer;

import jakarta.servlet.Filter;
import jakarta.servlet.http.HttpServletRequest;

import org.springframework.security.web.SecurityFilterChain;

/**
 * Alternative to
 * org.springframework.security.config.annotation.web.builders.HttpSecurity.
 */
public class HttpSecurityFilterChain implements SecurityFilterChain {

	@Override
	public boolean matches(HttpServletRequest request) {
		throw new UnsupportedOperationException("Auto-generated method stub");
	}

	@Override
	public List<Filter> getFilters() {
		throw new UnsupportedOperationException("Auto-generated method stub");
	}

	// FIXME we might start with a empty chain or we might start with some defaults

	public HttpSecurityFilterChain whenMatches(String string) {
		return null;
	}

	public static HttpSecurityFilterChain of(Consumer<HttpSecurityFilterChainConfigurer> filterChain) {
		return null;
	}

}
