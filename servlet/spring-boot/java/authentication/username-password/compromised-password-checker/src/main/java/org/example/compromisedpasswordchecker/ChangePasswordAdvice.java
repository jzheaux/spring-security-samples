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

public final class ChangePasswordAdvice {
	public static final ChangePasswordAdvice KEEP = new ChangePasswordAdvice();

	private final List<ChangePasswordReason> reasonsThatRequireResetting;
	private final List<ChangePasswordReason> reasonsThatRecommendResetting;

	private ChangePasswordAdvice() {
		this.reasonsThatRequireResetting = new ArrayList<>();
		this.reasonsThatRecommendResetting = new ArrayList<>();
	}

	public ChangePasswordAdvice(List<ChangePasswordReason> reasonsThatRequireResetting,
								List<ChangePasswordReason> reasonsThatRecommendResetting) {
		this.reasonsThatRequireResetting = reasonsThatRequireResetting;
		this.reasonsThatRecommendResetting = reasonsThatRecommendResetting;
	}

	public boolean requiresReset() {
		return !this.reasonsThatRequireResetting.isEmpty();
	}

	public boolean recommendsReset()  {
		return !requiresReset() && !this.reasonsThatRecommendResetting.isEmpty();
	}

	public static ChangePasswordAdvice require(ChangePasswordReason reason) {
		return builder().require(reason).build();
	}

	public static ChangePasswordAdvice recommend(ChangePasswordReason reason) {
		return builder().recommend(reason).build();
	}

	public static Builder builder() {
		return new Builder();
	}

	public static final class Builder {
		List<ChangePasswordReason> reasonsThatRequireResetting = new ArrayList<>();
		List<ChangePasswordReason> reasonsThatRecommendResetting = new ArrayList<>();

		private Builder() {

		}

		public Builder require(ChangePasswordReason reason) {
			this.reasonsThatRequireResetting.add(reason);
			return this;
		}

		public Builder recommend(ChangePasswordReason reason) {
			this.reasonsThatRecommendResetting.add(reason);
			return this;
		}

		public Builder advice(ChangePasswordAdvice advice) {
			this.reasonsThatRequireResetting.addAll(advice.reasonsThatRequireResetting);
			this.reasonsThatRecommendResetting.addAll(advice.reasonsThatRecommendResetting);
			return this;
		}

		public ChangePasswordAdvice build() {
			return new ChangePasswordAdvice(this.reasonsThatRequireResetting, this.reasonsThatRecommendResetting);
		}
	}
}
