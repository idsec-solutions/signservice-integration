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
package se.idsec.signservice.integration.core;

import java.util.NoSuchElementException;

/**
 * Generic cache interface for the SignService Integration Service.
 * 
 * @param <T>
 *          the type of the cached objects
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface IntegrationServiceCache<T> {

  /**
   * Gets an object from the cache.
   * <p>
   * Corresponds to {@code get(id, false)}.
   * </p>
   * 
   * @param id
   *          the object if
   * @return the object, or null if it does not exist
   */
  T get(final String id);

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
   * @return the object, or null if it does not exist
   */
  T get(final String id, final boolean remove);

  /**
   * Adds an object to the cache.
   * 
   * @param id
   *          the object ID
   * @param object
   *          the object to add
   */
  void put(final String id, final T object);

  /**
   * Adds an object to the cache and sets and explicit time when the object expires in the cache.
   * 
   * @param id
   *          the object ID
   * @param object
   *          the object to add
   * @param expires
   *          the expiration time (in millis since 1970)
   */
  void put(final String id, final T object, final long expires);

  /**
   * Sets an explicit expiration time for a cached object
   * 
   * @param id
   *          the object ID
   * @param expires
   *          the expiration time (in millis since 1970)
   * @throws NoSuchElementException
   *           if the object is not in the cache
   */
  void setExpires(final String id, final long expires) throws NoSuchElementException;

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

  /**
   * A predicate that tells if the cache implementation requires the supplied objects to be serializable to a string
   * object.
   * 
   * @return true if the objects should be serializable
   */
  boolean requiresSerializableObjects();

}
