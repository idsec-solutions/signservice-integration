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
package se.idsec.signservice.integration.document.pdf.visiblesig;

import java.io.Serial;

/**
 * Exception used to report errors in visible PDF signature requirements (that is not found by its validator).
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class VisiblePdfSignatureRequirementException extends Exception {

  /** For serializing. */
  @Serial
  private static final long serialVersionUID = 7153928242064492958L;

  /**
   * Constructor.
   *
   * @param message error message
   */
  public VisiblePdfSignatureRequirementException(final String message) {
    super(message);
  }

  /**
   * Constructor.
   *
   * @param message error message
   * @param cause the cause of the error
   */
  public VisiblePdfSignatureRequirementException(final String message, final Throwable cause) {
    super(message, cause);
  }

}
