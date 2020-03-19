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
package se.idsec.signservice.integration.core.impl;

import java.util.NoSuchElementException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import se.idsec.signservice.integration.core.IntegrationServiceCache;

/**
 * Base class for an in-memory implementation of the {@link IntegrationServiceCache} interface.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public abstract class AbstractInMemoryIntegrationServiceCache<T> implements IntegrationServiceCache<T> {

  /** The default max age (in millis) to keep an object in the cache. */
  public static final long MAX_AGE = 3600000L;

  /** The maximum time (in millis) to keep an object in the cache. Default is {@value #MAX_AGE}. */
  private long maxAge = MAX_AGE;
  
  /** The cache. */
  private ConcurrentMap<String, CacheEntry<T>> cache = new ConcurrentHashMap<>();
  
  /** {@inheritDoc} */
  @Override
  public T get(String id) {
    return this.get(id, false);
  }

  /** {@inheritDoc} */
  @Override
  public T get(final String id, final boolean remove) {
    CacheEntry<T> entry = this.cache.get(id);
    if (entry == null) {
      log.info("{}: Entry '{}' does not exist in cache", CorrelationID.id(), id);
      return null;
    }
    if (entry.isExpired()) {
      log.info("{}: Cached entry '{}' has expired", CorrelationID.id(), id);
      this.remove(id);
      return null;
    }
    if (remove) {
      log.trace("{}: Removing entry '{}' from cache", CorrelationID.id(), id);
      this.remove(id);
    }
    return entry.getObject();
  }

  /** {@inheritDoc} */
  @Override
  public void put(final String id, final T object) {
    this.put(id, object, System.currentTimeMillis() + this.maxAge);
  }

  /** {@inheritDoc} */
  @Override
  public void put(final String id, final T object, final long expires) {
    if (id == null) {
      log.error("{}: Attempt to cache object with no id", CorrelationID.id());
      throw new NullPointerException("Missing id");
    }
    if (object == null) {
      log.error("{}: Attempt to cache null object with id {}", CorrelationID.id(), id);
      throw new NullPointerException("Missing object");
    }
    if (expires < System.currentTimeMillis()) {
      log.warn("{}: Expiration time has already passed, will not cache object '{}'", CorrelationID.id(), id);
    }
    else {
      this.cache.put(id, new CacheEntry<T>(object, expires));
    }
  }

  /** {@inheritDoc} */
  @Override
  public void setExpires(final String id, final long expires) {
    T object = this.get(id, true);
    if (object == null) {
      log.warn("{}: The object '{}' is not cached - can not set expiration time", CorrelationID.id(), id);
      throw new NoSuchElementException("No such object in cache");
    }
    this.put(id, object, expires);
  }

  /** {@inheritDoc} */
  @Override
  public void remove(final String id) {
    this.cache.remove(id);
  }

  /** {@inheritDoc} */
  @Override
  public void clearExpired() {
    for (String id : this.cache.keySet()) {
      CacheEntry<T> entry = this.cache.get(id);
      if (entry.isExpired()) {
        log.debug("{}: Clearing expired cache entry '{}'", CorrelationID.id(), id);
        this.remove(id);
      }
    }
  }

  /**
   * Assigns the maximum time (in millis) to keep an object in the cache. Default is {@value #MAX_AGE}.
   * 
   * @param maxAge
   *          age in millis
   */
  public void setMaxAge(final long maxAge) {
    this.maxAge = maxAge;
  }

  /**
   * Class representing the cache entry.
   */
  private static class CacheEntry<T> {

    /** The cached object. */
    @Getter
    private final T object;

    /** The time when the object expires. */
    @Getter
    private final long expires;

    /**
     * Constructor.
     * 
     * @param object
     *          the object to cache.
     */
    public CacheEntry(final T object, final long expires) {
      this.object = object;
      this.expires = expires;
    }

    /**
     * Predicate telling if this entry has expired.
     * 
     * @return true if this entry has expired, and false otherwise
     */
    public boolean isExpired() {
      return this.expires < System.currentTimeMillis();
    }
  }

}
