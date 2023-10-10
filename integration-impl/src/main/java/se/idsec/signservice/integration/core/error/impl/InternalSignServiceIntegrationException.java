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
package se.idsec.signservice.integration.core.error.impl;

import jakarta.annotation.Nonnull;
import se.idsec.signservice.integration.core.error.ErrorCode;
import se.idsec.signservice.integration.core.error.SignServiceIntegrationCategoryException;

/**
 * Base exception class for internal errors.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class InternalSignServiceIntegrationException extends SignServiceIntegrationCategoryException {

  /** For serializing. */
  private static final long serialVersionUID = 6741232250952543045L;

  /**
   * Constructor.
   *
   * @param code
   *          the error code (within the given category)
   * @param message
   *          the error message
   */
  public InternalSignServiceIntegrationException(@Nonnull final ErrorCode.Code code, final String message) {
    super(code, message);
  }

  /**
   * Constructor.
   *
   * @param code
   *          the error code (within the given category)
   * @param message
   *          the error message
   * @param cause
   *          the cause of the error
   */
  public InternalSignServiceIntegrationException(@Nonnull final ErrorCode.Code code, final String message, final Throwable cause) {
    super(code, message, cause);
  }

  /** {@inheritDoc} */
  @Override
  public int getHttpStatus() {
    return 500;
  }

  /** {@inheritDoc} */
  @Override
  protected ErrorCode.Category getCategory() {
    return new ErrorCode.Category("internal");
  }

}
