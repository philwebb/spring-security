/*
 * Copyright 2026 the original author or authors.
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

package org.springframework.security.util.matcher;

import java.net.InetAddress;

import org.jspecify.annotations.Nullable;

/**
 * A negated {@link InetAddressMatcher}.
 *
 * @author Phillip Webb
 * @param matcher the matcher to negate
 */
record NegatedInetAddressMatcher(InetAddressMatcher matcher) implements InetAddressMatcher {

	@Override
	public boolean matches(@Nullable InetAddress address) {
		return !this.matcher.matches(address);
	}

	@Override
	public final String toString() {
		return "not " + this.matcher;
	}

}
