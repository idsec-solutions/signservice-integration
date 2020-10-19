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
package se.idsec.signservice.integration.app.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Configuration class for app settings.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Configuration
public class TestMySignatureConfiguration {

  /**
   * Gets the bean representing the base URL for the signature integration client.
   * 
   * @param contextPath
   *          the context path
   * @param baseUri
   *          the base URI for the application
   * @param serverPort
   *          the server port
   * @return the base URL
   */
  @Bean("signIntegrationBaseUrl")
  public String signIntegrationBaseUrl(
      @Value("${server.servlet.context-path}") String contextPath,
      @Value("${sp.base-uri}") String baseUri,
      @Value("${server.port}") int serverPort) {

    StringBuffer sb = new StringBuffer(baseUri);
    if (serverPort != 443) {
      sb.append(":").append(serverPort);
    }
    if (!contextPath.equals("/")) {
      sb.append(contextPath);
    }
    return sb.toString();
  }
  
  @Bean("debugReturnUrl")
  public String debugReturnUrl(@Value("${server.servlet.context-path}") final String contextPath, 
      @Value("${sp.debug-base-uri:}") final String debugBaseUri) {
    return String.format("%s%s/sign/response", debugBaseUri.trim(), contextPath.equals("/") ? "" : contextPath);
  }
  
  @Bean("signRequesterId")
  public String signRequesterId(@Value("${sp.entity-id}") final String signRequesterId) {
    return signRequesterId;
  }


}
