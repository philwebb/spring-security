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
 * @author Phillip Webb
 * @param <R>
 */
public interface RequestMatching {

	default RequestMatching whenMatches(DispatcherType... dispatcherTypes) {
		return whenMatches(null, dispatcherTypes);
	}

	default RequestMatching whenMatches(@Nullable HttpMethod method, DispatcherType... dispatcherTypes) {
		return whenMatches(Arrays.stream(dispatcherTypes)
			.map((dispatcherType) -> new DispatcherTypeRequestMatcher(dispatcherType, method))
			.toList());
	}

	default RequestMatching whenMatches(String... patterns) {
		return whenMatches(new Patterns(patterns));
	}

	default RequestMatching whenMatches(HttpMethod method, String... patterns) {
		return whenMatches(new Patterns(method, patterns));
	}

	default RequestMatching whenMatches(HttpMethod method) {
		return whenMatches(new Patterns(method));
	}

	RequestMatching whenMatches(Patterns patterns);

	default RequestMatching whenMatches(RequestMatcher... requestMatchers) {
		return whenMatches(List.of(requestMatchers));
	}

	RequestMatching whenMatches(Collection<? extends RequestMatcher> matchers);

	default RequestMatching ignoring(String... patterns) {
		return ignoring(new Patterns(patterns));
	}

	RequestMatching ignoring(Patterns patterns);

	default RequestMatching ignoring(RequestMatcher... matchers) {
		return ignoring(List.of(matchers));
	}

	RequestMatching ignoring(Collection<? extends RequestMatcher> matchers);

}
