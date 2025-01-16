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

import lombok.extern.slf4j.Slf4j;
import se.idsec.signservice.integration.core.IntegrationServiceCache;
import se.idsec.signservice.integration.core.error.NoAccessException;

import java.io.Serializable;
import java.util.Optional;

/**
 * Base class for an implementation of the {@link IntegrationServiceCache} interface.
 *
 * @param <T> the cachec object type
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public abstract class AbstractIntegrationServiceCache<T extends Serializable> implements IntegrationServiceCache<T> {

  /** The default max age (in millis) to keep an object in the cache. */
  public static final long MAX_AGE = 3600000L;

  /** The maximum time (in millis) to keep an object in the cache. Default is {@value #MAX_AGE}. */
  private long maxAge = MAX_AGE;

  /** {@inheritDoc} */
  @Override
  public T get(final String id, final String requesterId) throws NoAccessException {
    return this.get(id, false, requesterId);
  }

  /** {@inheritDoc} */
  @Override
  public T get(final String id, final boolean remove, final String requesterId) throws NoAccessException {
    final CacheEntry<T> entry = this.getCacheEntry(id);
    if (entry == null) {
      log.info("{}: Entry '{}' does not exist in cache", CorrelationID.id(), id);
      return null;
    }
    if (entry.getOwnerId() != null) {
      if (requesterId == null) {
        final String msg =
            String.format("Cached object '%s' has an registered owner - anonymous access is not allowed", id);
        log.error("{}: {}", CorrelationID.id(), msg);
        throw new NoAccessException(msg);
      }
      if (!requesterId.equals(entry.getOwnerId())) {
        final String msg =
            String.format("Cached object '%s' has an registered owner that does not match requester (%s)", id,
                requesterId);
        log.error("{}: {}", CorrelationID.id(), msg);
        throw new NoAccessException(msg);
      }
    }
    if (System.currentTimeMillis() > Optional.ofNullable(entry.getExpirationTime()).orElse(Long.MAX_VALUE)) {
      log.warn("{}: Cached entry '{}' has expired", CorrelationID.id(), id);
      this.remove(id);
      return null;
    }

    if (remove) {
      log.trace("{}: Removing entry '{}' from cache", CorrelationID.id(), id);
      this.remove(id);
    }
    return entry.getObject();
  }

  /**
   * Gets the cache entry identified by {@code id}.
   *
   * @param id the ID
   * @return the entry or null
   */
  protected abstract CacheEntry<T> getCacheEntry(final String id);

  /** {@inheritDoc} */
  @Override
  public void put(final String id, final T object, final String ownerId) {
    if (id == null) {
      log.error("{}: Attempt to cache object with no id", CorrelationID.id());
      throw new NullPointerException("Missing id");
    }
    if (object == null) {
      this.remove(id);
    }
    this.putCacheObject(id, object, ownerId, System.currentTimeMillis() + this.maxAge);
  }

  /**
   * Adds the supplied entry identified by {@code id} to the cache.
   *
   * @param id the ID
   * @param object the object to add
   * @param ownerId the owner of the object (may be null)
   * @param expirationTime expiration time (in millis)
   */
  protected abstract void putCacheObject(final String id, final T object, final String ownerId,
      final long expirationTime);

  /** {@inheritDoc} */
  @Override
  public void remove(final String id) {
    this.removeCacheObject(id);
  }

  /**
   * Removes the object identified by {@code id}.
   *
   * @param id the ID
   */
  protected abstract void removeCacheObject(final String id);

  /**
   * Assigns the maximum time (in millis) to keep an object in the cache. Default is {@value #MAX_AGE}.
   *
   * @param maxAge age in millis
   */
  public void setMaxAge(final long maxAge) {
    this.maxAge = maxAge;
  }

  /**
   * Representation of a cache entry.
   *
   * @param <T> the entry type
   */
  public interface CacheEntry<T extends Serializable> extends Serializable {

    /**
     * Gets the stored object.
     *
     * @return the stored object (never null)
     */
    T getObject();

    /**
     * Gets the owner identity.
     *
     * @return the owner id (may be null)
     */
    String getOwnerId();

    /**
     * Gets the expiration time (in millis since epoch).
     *
     * @return the expiration time (or null if the object should live until deleted)
     */
    Long getExpirationTime();

  }

}
