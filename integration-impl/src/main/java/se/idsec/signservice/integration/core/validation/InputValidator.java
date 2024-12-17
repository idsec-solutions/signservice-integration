/*
 * Copyright 2019-2023 IDsec Solutions AB
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package se.idsec.signservice.integration.core.validation;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import se.idsec.signservice.integration.core.error.InputValidationException;

/**
 * Interface for input validators.
 *
 * @param <T> the type of validation object
 * @param <H> hint type
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface InputValidator<T, H> {

  /**
   * Validates the supplied object using the supplied hint. The returned {@code ValidationResult} should be queried for
   * errors.
   *
   * @param object the object to validate
   * @param objectName the object name ({@code null} for no name)
   * @param hint an optional validation hint
   * @return a validation errors object
   */
  ValidationResult validate(
      @Nullable final T object, @Nullable final String objectName, @Nullable final H hint);

  /**
   * Validates the supplied object using the supplied hint and throws an {@code InputValidationException} for validation
   * errors.
   *
   * @param object the object to validate
   * @param objectName the object name
   * @param hint an optional validation hint
   * @throws InputValidationException for validation errors
   */
  void validateObject(
      @Nullable final T object, @Nonnull final String objectName, @Nullable final H hint)
      throws InputValidationException;

}
