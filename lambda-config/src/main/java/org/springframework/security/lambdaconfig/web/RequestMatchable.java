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

import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import jakarta.servlet.DispatcherType;

import org.springframework.http.HttpMethod;
import org.springframework.lang.Nullable;
import org.springframework.security.web.util.matcher.DispatcherTypeRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * @author pwebb
 * @param <R> The result type returned to allow fluent method chaining
 */
public interface RequestMatchable<R extends RequestMatchable<R>> {

	default R ifMatches(DispatcherType... dispatcherTypes) {
		return ifMatches(null, dispatcherTypes);
	}

	default R ifMatches(@Nullable HttpMethod method, DispatcherType... dispatcherTypes) {
		return ifMatches(Arrays.stream(dispatcherTypes)
			.map((dispatcherType) -> new DispatcherTypeRequestMatcher(dispatcherType, method))
			.toList());
	}

	default R ifMatches(String... patterns) {
		return ifMatches(new Patterns(patterns));
	}

	default R ifMatches(HttpMethod method, String... patterns) {
		return ifMatches(new Patterns(method, patterns));
	}

	default R ifMatches(HttpMethod method) {
		return ifMatches(new Patterns(method));
	}

	R ifMatches(Patterns patterns);

	default R ifMatches(RequestMatcher... requestMatchers) {
		return ifMatches(List.of(requestMatchers));
	}

	R ifMatches(Collection<? extends RequestMatcher> matchers);

	default R ignoring(String... patterns) {
		return ignoring(new Patterns(patterns));
	}

	R ignoring(Patterns patterns);

	default R ignoring(RequestMatcher... matchers) {
		return ignoring(List.of(matchers));
	}

	R ignoring(Collection<? extends RequestMatcher> matchers);

}
