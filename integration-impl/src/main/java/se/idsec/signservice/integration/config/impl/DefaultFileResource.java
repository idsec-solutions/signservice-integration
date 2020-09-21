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
package se.idsec.signservice.integration.config.impl;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import javax.annotation.PostConstruct;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import se.idsec.signservice.integration.core.FileResource;
import se.idsec.signservice.integration.core.ObjectBuilder;
import se.idsec.signservice.integration.document.ContentLoaderSingleton;

/**
 * A {@code DefaultFileResource} class is a generic class for handling file resources used in configuration of a
 * SignService Integration Service. Depending on how the service is configured a {@code DefaultFileResource} can be set
 * up in two different ways:
 * <ul>
 * <li>By giving the contents of the file resource (using {@link #setContents(String)}).</li>
 * <li>By giving a file resource string pointing at the file resource (see {@link #setResource(String)}). This is
 * typically the way a SignService Integration Service wants to configure its resources.</li>
 * </ul>
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@NoArgsConstructor
@AllArgsConstructor
@Builder
@JsonInclude(Include.NON_NULL)
@Slf4j
public class DefaultFileResource implements FileResource {

  /** The base64 encoded contents of the file resource. */
  private String contents;

  /** Optional descriptive string for the file resource. */
  private String description;

  /** The resource string for the file/resource. */
  @JsonIgnore
  private String resource;

  /**
   * If the {@code DefaultFileResource} object is initialized by a resource string the object can function in two modes;
   * it either loads the contents directly when the object is created using {@link #afterPropertiesSet()}
   * ({@code eagerlyLoadContents = true}), or it loads the contents every time it is asked for
   * ({@code eagerlyLoadContents = false}). The latter is the default and should be used if large documents that are
   * assigned to several configuration objects are handled. This will prevent a heavy memory usage at the cost of speed
   * in fetching the document contents.
   */
  @Builder.Default
  @JsonIgnore
  private boolean eagerlyLoadContents = false;

  /** {@inheritDoc} */
  @Override
  public String getContents() {
    if (this.contents == null && this.resource != null) {
      final String _contents = loadContentsFromResource(this.resource);
      if (this.eagerlyLoadContents) {
        // It seems like afterPropertiesSet didn't do its job, let's save the contents
        this.contents = _contents;
      }
      return _contents;
    }
    return this.contents;
  }

  /** {@inheritDoc} */
  @Override
  public void setContents(final String contents) {
    // Assert that the contents is a valid Base64 encoding (will throw if not) ...
    Base64.getDecoder().decode(contents);
    this.contents = contents;
  }

  /**
   * Assigns the raw file resource contents.
   * 
   * @param contents
   *          the raw file resource contents
   */
  public void setContents(final byte[] contents) {
    this.setContents(new String(Base64.getEncoder().encode(contents), StandardCharsets.UTF_8));
  }

  /** {@inheritDoc} */
  @Override
  public String getDescription() {
    return this.description;
  }

  /** {@inheritDoc} */
  @Override
  public void setDescription(final String description) {
    this.description = description;
  }

  /**
   * If the {@code DefaultFileResource} object was initialized with a {@code resource} string this method returns this
   * string.
   * 
   * @return the file resource string or null if none is set
   */
  public String getResource() {
    return this.resource;
  }

  /**
   * Assigns a resource string.
   * 
   * <p>
   * Note: The Spring Framework style of representing a resource should be used. For example: {@code classpath:xyz.svg}
   * and {@code file:/path/xyz.svg}.
   * </p>
   * 
   * @param resource
   *          the resource string
   */
  public void setResource(final String resource) {
    this.resource = resource;
  }

  /**
   * If the {@code DefaultFileResource} object is initialized by a resource string the object can function in two modes;
   * it either loads the contents directly when the object is created using {@link #afterPropertiesSet()}
   * ({@code eagerlyLoadContents = true}), or it loads the contents every time it is asked for
   * ({@code eagerlyLoadContents = false}). The latter is the default and should be used if large documents that are
   * assigned to several configuration objects are handled. This will prevent a heavy memory usage at the cost of speed
   * in fetching the document contents.
   * 
   * @param eagerlyLoadContents
   *          whether to load contents eagerly or not
   */
  public void setEagerlyLoadContents(boolean eagerlyLoadContents) {
    this.eagerlyLoadContents = eagerlyLoadContents;
  }

  /**
   * Checks that the file resource is correctly initialized, and if {@code eagerlyLoadContents} is {@code true} it
   * also loads the contents (if necessary).
   * 
   * <p>
   * Note: If executing in a Spring Framework environment this method is automatically invoked after all properties have
   * been assigned. Otherwise it should be explicitly invoked.
   * </p>
   * 
   * @throws Exception
   *           for init errors
   */
  @PostConstruct
  public void afterPropertiesSet() throws Exception {
    if (this.contents == null && this.resource == null) {
      throw new Exception("Either contents or resource must be set");
    }
    if (this.contents != null && this.resource != null) {
      log.warn("Both contents and resource has been set for DefaultFileResource, resource string will be ignored");
      this.resource = null;
    }
    if (this.contents == null && this.resource != null && this.eagerlyLoadContents) {
      this.contents = loadContentsFromResource(this.resource);
      log.info("Successfully loaded contents from {}", this.resource);
      this.resource = null;
    }
  }

  /**
   * Helper method that loads contents from a resource.
   * 
   * @param resource
   *          the resource string
   * @return the Base64 encoded contents
   */
  private static String loadContentsFromResource(final String resource) {
    if (resource != null) {
      try {
        final byte[] contents = ContentLoaderSingleton.getInstance().loadContent(resource);
        return Base64.getEncoder().encodeToString(contents);
      }
      catch (IOException e) {
        final String msg = String.format("Failed to load contents from '%s' - %s", resource, e.getMessage());
        log.error("{}", msg, e);
        throw new RuntimeException(msg, e);
      }
    }
    return null;
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    StringBuilder builder = new StringBuilder();
    builder.append("contents=");
    if (this.contents != null) {
      builder.append("{size=").append(this.contents.length()).append("}");
    }
    else {
      builder.append("<not set>");
    }
    if (this.description != null) {
      builder.append(",description=\"").append(this.description).append("\"");
    }
    if (this.resource != null) {
      builder.append(",resource=\"").append(this.resource).append("\"");
    }
    builder.append(",eagerlyLoadContents=").append(eagerlyLoadContents);
    return builder.toString();
  }

  /**
   * Builder class for {@link DefaultFileResource}.
   */
  public static class DefaultFileResourceBuilder implements ObjectBuilder<DefaultFileResource> {
    private boolean eagerlyLoadContents = false;
    
    // Lombok
  }
  
}
