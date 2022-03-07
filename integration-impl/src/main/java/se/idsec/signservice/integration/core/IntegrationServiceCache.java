/*
 * Copyright 2019-2022 IDsec Solutions AB
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
package se.idsec.signservice.integration.core;

import java.io.Serializable;

import se.idsec.signservice.integration.core.error.NoAccessException;

/**
 * Generic cache interface for the SignService Integration Service.
 *
 * @param <T>
 *          the type of the cached objects
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface IntegrationServiceCache<T extends Serializable> {

  /**
   * Gets an object from the cache.
   * <p>
   * Corresponds to {@code get(id, false)}.
   * </p>
   *
   * @param id
   *          the object if
   * @param requesterId
   *          optional ID of the requesting actor
   * @return the object, or null if it does not exist
   * @throws NoAccessException
   *           if the owner of the cached object does not match the requester ID
   */
  T get(final String id, final String requesterId) throws NoAccessException;

  /**
   * Gets an object from the cache.
   * <p>
   * If the {@code remove} flag is set, the cached object is removed from the cache.
   * </p>
   *
   * @param id
   *          the object ID
   * @param remove
   *          if set, the returned object is removed from the cache
   * @param requesterId
   *          optional ID of the requesting actor
   * @return the object, or null if it does not exist
   * @throws NoAccessException
   *           if the owner of the cached object does not match the requester ID
   */
  T get(final String id, final boolean remove, final String requesterId) throws NoAccessException;

  /**
   * Adds an object to the cache.
   *
   * @param id
   *          the object ID
   * @param object
   *          the object to add
   * @param ownerId
   *          the owner identity (may be null)
   */
  void put(final String id, final T object, final String ownerId);

  /**
   * Deletes an object having the given ID from the cache.
   *
   * @param id
   *          the object ID
   */
  void remove(final String id);

  /**
   * Utility method that removes expired entries. Should be called by a scheduled task.
   */
  void clearExpired();

}
