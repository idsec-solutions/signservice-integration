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
package se.idsec.signservice.integration.core.impl;

import jakarta.annotation.Nullable;
import lombok.Getter;
import lombok.Setter;

import java.util.UUID;

/**
 * Singleton that holds a correlation ID in TLS.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class CorrelationID {

  /** The correlation ID. */
  @Setter
  @Getter
  private String correlationID;

  /** The ThreadLocal ... */
  private final static ThreadLocal<CorrelationID> THREAD_LOCAL = ThreadLocal.withInitial(CorrelationID::new);

  /**
   * Is called to initialize the correlation ID. If no correlation ID is assigned, a random value will be inserted.
   *
   * @param id the correlation ID (or null)
   */
  public static void init(@Nullable final String id) {
    THREAD_LOCAL.get().setCorrelationID(id != null ? id : UUID.randomUUID().toString());
  }

  /**
   * Returns this thread's correlation ID.
   *
   * @return the correlation ID
   */
  public static String id() {
    return THREAD_LOCAL.get().getCorrelationID();
  }

  /**
   * Removes the current correlation ID.
   */
  public static void clear() {
    THREAD_LOCAL.remove();
  }

  // Hidden constructor
  private CorrelationID() {
  }

}
