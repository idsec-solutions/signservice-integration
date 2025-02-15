/*
 * Copyright 2019-2025 IDsec Solutions AB
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

import se.idsec.signservice.integration.core.error.ErrorCode;

import java.io.Serial;

/**
 * Exception class for protocol related errors.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class SignServiceProtocolException extends InternalSignServiceIntegrationException {

  /** For serializing. */
  @Serial
  private static final long serialVersionUID = -9056039254424787720L;

  /**
   * Constructor.
   *
   * @param message the error message
   */
  public SignServiceProtocolException(final String message) {
    this(message, null);
  }

  /**
   * Constructor.
   *
   * @param message the error message
   * @param cause the cause of the error
   */
  public SignServiceProtocolException(final String message, final Throwable cause) {
    super(new ErrorCode.Code("protocol"), message, cause);
  }

}
