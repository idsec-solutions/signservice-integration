/*
 * Copyright 2019 IDsec Solutions AB
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
package se.idsec.signservice.integration.security;

import se.idsec.signservice.integration.core.error.ErrorCode;

/**
 * Exception class for errors during metadata processing.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class MetadataException extends SignServiceEncryptException {

  /** The error code for metadata errors. */
  public static final ErrorCode.Code METADATA_ERROR = new ErrorCode.Code("metadata-error");

  /** For serializing. */
  private static final long serialVersionUID = -5064259813044502880L;

  /**
   * Constructor.
   * 
   * @param message
   *          the error message
   */
  public MetadataException(final String message) {
    super(METADATA_ERROR, message);
  }

  /**
   * Constructor.
   * 
   * @param message
   *          the error message
   * @param cause
   *          the cause of the error
   */
  public MetadataException(final String message, final Throwable cause) {
    super(METADATA_ERROR, message, cause);
  }

}
