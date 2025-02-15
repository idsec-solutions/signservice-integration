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
package se.idsec.signservice.integration.state;

import se.idsec.signservice.integration.core.IntegrationServiceCache;

/**
 * Interface for the SignService Integration Service state cache.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface IntegrationServiceStateCache extends IntegrationServiceCache<CacheableSignatureState> {

  /**
   * Adds an object to the cache.
   *
   * @param id the object ID
   * @param state the state object to add
   */
  default void put(final String id, final CacheableSignatureState state) {
    this.put(id, state, state != null ? state.getOwnerId() : null);
  }

}
