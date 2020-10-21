/*
 * Copyright 2019-2020 IDsec Solutions AB
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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.extern.slf4j.Slf4j;
import se.idsec.signservice.dss.DSSStatusCodes;
import se.idsec.signservice.integration.SignResponseCancelStatusException;
import se.idsec.signservice.integration.SignResponseErrorStatusException;
import se.idsec.signservice.integration.core.error.ErrorCode;
import se.idsec.signservice.integration.core.error.InputValidationException;
import se.idsec.signservice.integration.core.error.SignServiceIntegrationErrorBody;
import se.idsec.signservice.integration.core.error.SignServiceIntegrationException;
import se.idsec.signservice.integration.document.pdf.PdfSignaturePageFullException;

/**
 * Utilities for error handling.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class SignServiceIntegrationErrorUtils {

  /** For JSON deserialization. */
  private static final ObjectMapper objectMapper = new ObjectMapper();

  /**
   * A utility method that can be used by clients to a SignService Integration service running as a REST server. The
   * method converts the error body into an exception.
   * 
   * @param errorBody
   *          the error body
   * @return an exception
   */
  public static Exception toException(final String errorBody) {
    try {
      final SignServiceIntegrationErrorBody body = objectMapper.readValue(errorBody, SignServiceIntegrationErrorBody.class);

      if (body.getDssError() != null) {
        if (DSSStatusCodes.DSS_MINOR_USER_CANCEL.equals(body.getDssError().getMinorCode())) {
          return new SignResponseCancelStatusException();
        }
        else {
          return new SignResponseErrorStatusException(body.getDssError().getMajorCode(), body.getDssError().getMinorCode());
        }
      }
      if (body.getValidationError() != null) {
        if (body.getValidationError().getDetails() != null) {
          return new InputValidationException(body.getValidationError().getObject(), body.getMessage(),
            body.getValidationError().getDetails());
        }
        else {
          return new InputValidationException(body.getValidationError().getObject(), body.getMessage());
        }
      }
      if (PdfSignaturePageFullException.class.getName().equals(body.getExceptionClass())) {
        return new PdfSignaturePageFullException(body.getMessage());
      }

      // Else, return a generic exception ...
      return new GenericSignServiceIntegrationException(
        new ErrorCode(body.getErrorCode()), body.getMessage(), body.getStatus());
    }
    catch (JsonProcessingException e) {
      log.error("Could not map errorBody to SignServiceIntegrationErrorBody", e);
      return new InternalSignServiceIntegrationException(new ErrorCode.Code("unknown"), "Unknwon error " + errorBody);
    }
  }

  // Hidden constructor
  private SignServiceIntegrationErrorUtils() {
  }

  /**
   * Exception class used internally by {@link SignServiceIntegrationErrorUtils#toException(String)}.
   */
  private static class GenericSignServiceIntegrationException extends SignServiceIntegrationException {

    /** For serializing. */
    private static final long serialVersionUID = -24745654127673732L;

    /** The HTTP status code. */
    final int httpStatus;

    /**
     * Constructor.
     * 
     * @param errorCode
     *          the error code
     * @param message
     *          the error message
     * @param httpStatus
     *          the HTTP status
     */
    public GenericSignServiceIntegrationException(final ErrorCode errorCode, final String message, final int httpStatus) {
      super(errorCode, message);
      this.httpStatus = httpStatus;
    }

    /** {@inheritDoc} */
    @Override
    public int getHttpStatus() {
      return this.httpStatus;
    }

  }

}
