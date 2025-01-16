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
package se.idsec.signservice.integration.core.validation;

import java.util.HashMap;
import java.util.Map;

/**
 * Class holding validation results (errors).
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class ValidationResult {

  /** The name for the object that is validated. */
  final private String objectName;

  /** Error message for "global error", i.e., an error reported directly on the object. */
  private String globalError;

  /** Underlying errors (field names and error messages). */
  private final Map<String, String> fieldErrors = new HashMap<>();

  /**
   * Constructor.
   *
   * @param objectName the name for the object that is validated (null for no name)
   */
  public ValidationResult(final String objectName) {
    this.objectName = objectName;
  }

  /**
   * Gets the name for the object that was validated.
   *
   * @return the name for the object that was validated (null if the object isn't given a name)
   */
  public String getObjectName() {
    return this.objectName;
  }

  /**
   * Predicate telling if this object holds any errors.
   *
   * @return true if this object holds errors and false otherwise
   */
  public boolean hasErrors() {
    return this.globalError != null || !this.fieldErrors.isEmpty();
  }

  /**
   * Returns the global error message for this object (if any)
   *
   * @return the global error message or null
   */
  public String getGlobalError() {
    return this.globalError;
  }

  /**
   * Returns the "field" errors of this object.
   *
   * @return a map (possibly empty) with field names and their error messages
   */
  public Map<String, String> getFieldErrors() {
    return this.fieldErrors;
  }

  /**
   * Register an error for the entire object.
   *
   * @param msg the error message
   */
  public void reject(final String msg) {
    this.globalError = msg;
  }

  /**
   * Register an error for a specific field.
   *
   * @param field the field name
   * @param msg the error message
   */
  public void rejectValue(final String field, final String msg) {
    if (this.objectName != null) {
      this.fieldErrors.put(String.format("%s.%s", this.objectName, field), msg);
    }
    else {
      this.fieldErrors.put(field, msg);
    }
  }

  /**
   * If an underlying object (to this object) has been verified, its result should be installed.
   *
   * @param result the result from the underlying object
   */
  public void setFieldErrors(final ValidationResult result) {
    if (result.hasErrors()) {
      if (result.getGlobalError() != null) {
        if (result.getObjectName() != null) {
          this.rejectValue(result.getObjectName(), result.getGlobalError());
        }
        else {
          this.rejectValue(this.getObjectName(), result.getGlobalError());
        }
      }
      for (final Map.Entry<String, String> fe : result.getFieldErrors().entrySet()) {
        this.rejectValue(fe.getKey(), fe.getValue());
      }
    }
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    final StringBuilder sb = new StringBuilder(this.objectName);
    sb.append(":");
    if (!this.hasErrors()) {
      sb.append(" Success");
    }
    else {
      if (this.globalError != null) {
        sb.append(" '").append(this.globalError).append("'.");
      }
      if (!this.fieldErrors.isEmpty()) {
        sb.append(" Details: ").append(this.fieldErrors);
      }
    }
    return sb.toString();
  }

}
