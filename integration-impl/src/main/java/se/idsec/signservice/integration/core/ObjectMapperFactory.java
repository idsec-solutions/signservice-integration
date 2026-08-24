/*
 * Copyright 2019-2026 IDsec Solutions AB
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

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Singleton factory for getting an ObjectMapper instance.
 * <p>
 * By using this factory, a pre-configured ObjectMapper instance can be obtained.
 * </p>
 *
 * @author Martin Lindström
 */
public class ObjectMapperFactory {

  // The configured object mapper instance
  private ObjectMapper objectMapper;

  private static final ObjectMapperFactory INSTANCE = new ObjectMapperFactory();

  /**
   * Returns the ObjectMapper instance.
   *
   * @return the ObjectMapper instance
   */
  public static ObjectMapperFactory getInstance() {
    return INSTANCE;
  }

  /**
   * If an ObjectMapper instance has been configured, it is returned. Otherwise a new instance is created.
   *
   * @return the ObjectMapper instance
   */
  public ObjectMapper getObjectMapper() {
    if (this.objectMapper != null) {
      return this.objectMapper;
    }
    else {
      final ObjectMapper mapper = new ObjectMapper();
      mapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
      this.objectMapper = mapper;
      return mapper;
    }
  }

  /**
   * Assigns the ObjectMapper instance.
   *
   * @param objectMapper the ObjectMapper instance
   */
  public void setObjectMapper(final ObjectMapper objectMapper) {
    this.objectMapper = objectMapper;
  }

  // Hidden constructor
  private ObjectMapperFactory() {
  }

}
