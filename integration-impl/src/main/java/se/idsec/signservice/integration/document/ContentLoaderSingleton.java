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
package se.idsec.signservice.integration.document;

import java.io.IOException;

import lombok.extern.slf4j.Slf4j;
import se.idsec.signservice.integration.document.impl.SpringContentLoader;

/**
 * Since it should be possible to use this library without Spring Framework we use a global {@link ContentLoader}. The
 * default implementation relies on a Spring implementation, but if Spring isn't used another implementation may be
 * used by assigning it using {@link #setContentLoader(ContentLoader)}.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class ContentLoaderSingleton implements ContentLoader {

  /** The content loader used. */
  private ContentLoader contentLoader;

  /** The singleton instance. */
  private final static ContentLoaderSingleton INSTANCE = new ContentLoaderSingleton();

  /**
   * Gets the singleton instance of the global content loader.
   * 
   * @return a ContentLoader
   */
  public static ContentLoader getInstance() {
    return INSTANCE;
  }

  /** {@inheritDoc} */
  @Override
  public byte[] loadContent(final String resource) throws IOException {
    return this.getContentLoader().loadContent(resource);
  }

  /**
   * If the global {@link ContentLoader} should be something else than {@link SpringContentLoader} this method should be
   * used to assign this.
   * 
   * @param loader
   *          the content loader to set
   */
  public void setContentLoader(final ContentLoader loader) {
    if (this.contentLoader != null) {
      throw new IllegalArgumentException("Global ContentLoader has already been configured");
    }
    if (loader != null) {
      log.info("Setting global content loader: {}", loader.getClass().getName());
      this.contentLoader = loader;
    }
  }

  /**
   * Gets the {@link ContentLoader} to use. If a specific content loader has not been assigned (using
   * {@link #setContentLoader(ContentLoader)}) an {@link SpringContentLoader} instance will be used.
   * 
   * @return the content loader to use
   */
  private ContentLoader getContentLoader() {
    if (this.contentLoader == null) {
      this.contentLoader = new SpringContentLoader();
    }
    return this.contentLoader;
  }

  // Hidden constructor
  private ContentLoaderSingleton() {
  }

}
