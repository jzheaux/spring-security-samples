/*
 * Copyright 2025 the original author or authors.
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

package org.example.compromisedpasswordchecker;

import java.util.Collection;

public interface ChangePasswordAdvice {

	enum Action {
		KEEP, CHANGE, REQUIRE_CHANGE
	}

	default Action getAction() {
		if (!getRequireChangeReasons().isEmpty()) {
			return Action.REQUIRE_CHANGE;
		}
		if (!getChangeReasons().isEmpty()) {
			return Action.CHANGE;
		}
		return Action.KEEP;
	}

	Collection<ChangePasswordReason> getRequireChangeReasons();

	Collection<ChangePasswordReason> getChangeReasons();

	static ChangePasswordAdvice keep() {
		return new DefaultChangePasswordAdvice();
	}

	static ChangePasswordAdvice require(ChangePasswordReason reason) {
		return DefaultChangePasswordAdvice.builder().require((r) -> r.add(reason)).build();
	}

	static ChangePasswordAdvice recommend(ChangePasswordReason reason) {
		return DefaultChangePasswordAdvice.builder().recommend((r) -> r.add(reason)).build();
	}
}
