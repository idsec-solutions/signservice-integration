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

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLContext;

import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.ssl.TrustStrategy;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.http.client.support.BasicAuthenticationInterceptor;
import org.springframework.web.client.RestTemplate;

/**
 * Configuration for using the SignService Integration API as a REST client.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Configuration
@ConditionalOnProperty(name = "signservice.rest.enabled", havingValue = "true")
public class RestSignServiceIntegrationConfiguration {

  @Bean("restServerUrl")
  public String restServerUrl(@Value("${signservice.rest.server-url}") final String serverUrl) {
    return serverUrl;
  }

  @Bean
  public RestTemplate restTemplate(
      @Qualifier("restServerUrl") final String serverUrl,
      @Value("${signservice.rest.client-username}") final String username,
      @Value("${signservice.rest.client-password}") final String password) throws Exception {
    
    final SSLContext sslContext = new SSLContextBuilder().loadTrustMaterial(
      new TrustStrategy() {
        @Override
        public boolean isTrusted(X509Certificate[] chain, String authType) throws CertificateException {
          return true;
        }
      }).build();

    final CloseableHttpClient httpClient = HttpClients.custom()
//      .setSSLHostnameVerifier(new NoopHostnameVerifier())
      .setSSLContext(sslContext)
      .disableRedirectHandling()
      .build();

    final HttpComponentsClientHttpRequestFactory requestFactory = new HttpComponentsClientHttpRequestFactory();
    requestFactory.setHttpClient(httpClient);

    RestTemplate restTemplate = new RestTemplate(requestFactory);
    restTemplate.getInterceptors().add(new BasicAuthenticationInterceptor(username, password));

    return restTemplate;
  }

}
