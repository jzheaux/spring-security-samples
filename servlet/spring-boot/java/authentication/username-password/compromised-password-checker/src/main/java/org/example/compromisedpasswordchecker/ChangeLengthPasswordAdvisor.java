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

public class ChangeLengthPasswordAdvisor implements ChangePasswordAdvisor {
	private final int minLength;
	private final int maxLength;

	public ChangeLengthPasswordAdvisor(int minLength) {
		this(minLength, Integer.MAX_VALUE);
	}

	public ChangeLengthPasswordAdvisor(int minLength, int maxLength) {
		this.minLength = minLength;
		this.maxLength = maxLength;
	}

	@Override
	public ChangePasswordAdvice advise(ChangePasswordAdviceRequest request) {
		if (request.password().length() < this.minLength) {
			return ChangePasswordAdvice.require(ChangePasswordReason.TOO_SHORT);
		}
		if (request.password().length() > this.maxLength) {
			return ChangePasswordAdvice.recommend(ChangePasswordReason.TOO_LONG);
		}
		return ChangePasswordAdvice.KEEP;
	}
}
