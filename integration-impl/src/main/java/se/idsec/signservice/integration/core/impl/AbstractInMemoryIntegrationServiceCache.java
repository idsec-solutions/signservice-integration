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
package se.idsec.signservice.integration.core.impl;

import lombok.extern.slf4j.Slf4j;
import se.idsec.signservice.integration.core.IntegrationServiceCache;

import java.io.Serial;
import java.io.Serializable;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Base class for an in-memory implementation of the {@link IntegrationServiceCache} interface.
 *
 * @param <T> the cached object type
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public abstract class AbstractInMemoryIntegrationServiceCache<T extends Serializable>
    extends AbstractIntegrationServiceCache<T> {

  /** The cache. */
  private final ConcurrentMap<String, InMemoryCacheEntry<T>> cache = new ConcurrentHashMap<>();

  /** {@inheritDoc} */
  @Override
  protected CacheEntry<T> getCacheEntry(final String id) {
    return this.cache.get(id);
  }

  /** {@inheritDoc} */
  @Override
  protected void putCacheObject(final String id, final T object, final String ownerId, final long expirationTime) {
    this.cache.put(id, new InMemoryCacheEntry<>(object, ownerId, expirationTime));
  }

  /** {@inheritDoc} */
  @Override
  protected void removeCacheObject(final String id) {
    this.cache.remove(id);
  }

  /** {@inheritDoc} */
  @Override
  public void clearExpired() {
    for (final String id : this.cache.keySet()) {
      final CacheEntry<T> entry = this.cache.get(id);
      if (System.currentTimeMillis() > Optional.ofNullable(entry.getExpirationTime()).orElse(Long.MAX_VALUE)) {
        log.debug("{}: Clearing expired cache entry '{}'", CorrelationID.id(), id);
        this.remove(id);
      }
    }
  }

  /**
   * Class representing the cache entry.
   *
   * @param <T> the entry type
   */
  public static class InMemoryCacheEntry<T extends Serializable> implements CacheEntry<T> {

    /** For serializing. */
    @Serial
    private static final long serialVersionUID = 6027367800009250991L;

    /** The cached object. */
    private final T object;

    /** The time when the object expires. */
    private final long expirationTime;

    /** The owner id. */
    private final String ownerId;

    /**
     * Constructor.
     *
     * @param object the object to cache.
     * @param ownerId the owner identity (may be null)
     * @param expirationTime the expiration time
     */
    public InMemoryCacheEntry(final T object, final String ownerId, final long expirationTime) {
      this.object = object;
      this.ownerId = ownerId;
      this.expirationTime = expirationTime;
    }

    /** {@inheritDoc} */
    @Override
    public T getObject() {
      return this.object;
    }

    /** {@inheritDoc} */
    @Override
    public String getOwnerId() {
      return this.ownerId;
    }

    /** {@inheritDoc} */
    @Override
    public Long getExpirationTime() {
      return this.expirationTime;
    }

  }

}
