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

import java.util.ArrayList;
import java.util.List;

public final class DefaultChangePasswordAdvice implements ChangePasswordAdvice {

	private final List<ChangePasswordReason> requireReasons;
	private final List<ChangePasswordReason> recommendReasons;

	DefaultChangePasswordAdvice() {
		this(new ArrayList<>(), new ArrayList<>());
	}

	public DefaultChangePasswordAdvice(List<ChangePasswordReason> requireReasons,
								List<ChangePasswordReason> recommendReasons) {
		this.requireReasons = List.copyOf(requireReasons);
		this.recommendReasons = List.copyOf(recommendReasons);
	}

	@Override
	public List<ChangePasswordReason> getRequireChangeReasons() {
		return this.requireReasons;
	}

	@Override
	public List<ChangePasswordReason> getChangeReasons() {
		return this.recommendReasons;
	}

	public static Builder builder() {
		return new Builder();
	}

	public static final class Builder {
		List<ChangePasswordReason> requireReasons = new ArrayList<>();
		List<ChangePasswordReason> recommendReasons = new ArrayList<>();

		private Builder() {

		}

		public Builder require(ChangePasswordReason reason) {
			this.requireReasons.add(reason);
			return this;
		}

		public Builder recommend(ChangePasswordReason reason) {
			this.recommendReasons.add(reason);
			return this;
		}

		public Builder advice(ChangePasswordAdvice advice) {
			this.requireReasons.addAll(advice.getRequireChangeReasons());
			this.recommendReasons.addAll(advice.getChangeReasons());
			return this;
		}

		public DefaultChangePasswordAdvice build() {
			return new DefaultChangePasswordAdvice(this.requireReasons, this.recommendReasons);
		}
	}
}
