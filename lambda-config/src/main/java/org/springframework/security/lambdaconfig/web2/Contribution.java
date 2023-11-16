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

/**
 * A contribution returned from a {@link Contributor} that is used to apply
 * configuration.
 *
 * @author Phillip Webb
 * @param <T> the type that the contribution supports
 * @see Contributor
 */
@FunctionalInterface
public interface Contribution<T> {

	default void prepare(SharedObjects sharedObjects) {
	}

	void apply(SharedObjects sharedObjects, T instance);

}
