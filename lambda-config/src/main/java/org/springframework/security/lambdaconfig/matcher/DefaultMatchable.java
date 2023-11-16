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

package org.springframework.security.lambdaconfig.matcher;

import java.util.Collection;
import java.util.function.Function;

import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * @param <R>
 * @author pwebb
 */
class DefaultMatchable<R> implements Matchable<R> {

	private final Function<Patterns, RequestMatcher> requestMatcherFactory;

	private final Function<Matchable<R>, R> resultSupplier;

	DefaultMatchable(Function<Patterns, RequestMatcher> requestMatcherFactory,
			Function<Matchable<R>, R> resultSupplier) {
		this.requestMatcherFactory = requestMatcherFactory;
		this.resultSupplier = resultSupplier;
	}

	@Override
	public R whenMatches(Patterns patterns) {
		return whenMatches(this.requestMatcherFactory.apply(patterns));
	}

	@Override
	public R whenMatches(Collection<? extends RequestMatcher> matchers) {
		return result();
	}

	@Override
	public R ignoring(Patterns patterns) {
		return ignoring(this.requestMatcherFactory.apply(patterns));
	}

	@Override
	public R ignoring(Collection<? extends RequestMatcher> matchers) {
		return result();
	}

	private R result() {
		return this.resultSupplier.apply(this);
	}

}
