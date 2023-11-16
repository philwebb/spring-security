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

import org.junit.jupiter.api.Test;

import org.springframework.security.web.util.matcher.RequestMatcher;

import static org.junit.jupiter.api.Assertions.fail;

/**
 * @author pwebb
 */
class MatchableTests {

	@Test
	void test() {
		fail("Not yet implemented");
	}

	static class Mutable implements Matchable<Mutable> {

		private final Matchable<Mutable> matchable;

		public Mutable(Function<Patterns, RequestMatcher> requestMatcherFactory) {
			this.matchable = Matchable.createWithFixedResult(requestMatcherFactory, this);
		}

		@Override
		public Mutable whenMatches(Patterns patterns) {
			return this.matchable.whenMatches(patterns);
		}

		@Override
		public Mutable whenMatches(Collection<? extends RequestMatcher> matchers) {
			return this.matchable.whenMatches(matchers);
		}

		@Override
		public Mutable ignoring(Patterns patterns) {
			return this.matchable.ignoring(patterns);
		}

		@Override
		public Mutable ignoring(Collection<? extends RequestMatcher> matchers) {
			return this.matchable.ignoring(matchers);
		}

	}

	static class Immutable implements Matchable<Immutable> {

		private final Matchable<Immutable> matchable;

		public Immutable(Function<Patterns, RequestMatcher> requestMatcherFactory) {
			this.matchable = Matchable.create(requestMatcherFactory, Immutable::new);
		}

		public Immutable(Matchable<Immutable> matchable) {
			this.matchable = matchable;
		}

		@Override
		public Immutable whenMatches(Patterns patterns) {
			return this.matchable.whenMatches(patterns);
		}

		@Override
		public Immutable whenMatches(Collection<? extends RequestMatcher> matchers) {
			return this.matchable.whenMatches(matchers);
		}

		@Override
		public Immutable ignoring(Patterns patterns) {
			return this.matchable.ignoring(patterns);
		}

		@Override
		public Immutable ignoring(Collection<? extends RequestMatcher> matchers) {
			return this.matchable.ignoring(matchers);
		}

	}

}
