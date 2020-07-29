/*
 * Copyright 2002-2018 the original author or authors.
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

package org.springframework.security.config.http;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Assertions for tests that rely on confirming behavior of the package-private
 * SecurityFilters enum
 *
 * @author Josh Cummings
 */
public final class SecurityFiltersAssertions {

	private static Collection<SecurityFilters> ordered = Arrays.asList(SecurityFilters.values());

	private SecurityFiltersAssertions() {
	}

	public static void assertEquals(List<String> filters) {
		List<String> expected = ordered.stream().map(SecurityFilters::name).collect(Collectors.toList());
		assertThat(filters).isEqualTo(expected);
	}

}
