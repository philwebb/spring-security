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

import java.util.function.Consumer;

import org.springframework.security.lambdaconfig.web2.Csrf.Configurer;

public final class Csrf implements SecurityFilterChainContributor<Configurer> {

	private static final Csrf INSTANCE = new Csrf();

	static Csrf instance() {
		return INSTANCE;
	}

	private Csrf() {
	}

	@Override
	public SecurityContribution<SecurityFilterChainBuilder> contribute(Consumer<Configurer> csrf) {
		CsrfContribution contribution = new CsrfContribution();
		csrf.accept(contribution);
		return contribution;
	}

	interface Configurer {

		void setThing1(Object thing1);

		void setThing2(Object thing2);

		void addThings(Object things);

	}

}
