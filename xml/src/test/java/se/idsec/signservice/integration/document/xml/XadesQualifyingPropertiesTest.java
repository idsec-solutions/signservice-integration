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
package se.idsec.signservice.integration.document.xml;

import org.junit.Assert;
import org.junit.Test;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.w3c.dom.Element;

import se.idsec.signservice.xml.DOMUtils;

/**
 * Test cases for XadesQualifyingProperties.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class XadesQualifyingPropertiesTest {

  @Test
  public void testDecode() throws Exception {

    Resource dsObjectResource = new ClassPathResource("ds-object.xml");
    Element dsObjectElement = DOMUtils.inputStreamToDocument(dsObjectResource.getInputStream()).getDocumentElement();

    XadesQualifyingProperties xqp = XadesQualifyingProperties.createXadesQualifyingProperties(dsObjectElement);
    Assert.assertNotNull(xqp.getSigningCertificateDigest());
    Assert.assertNotNull(xqp.getSigningTime());
    
    dsObjectResource = new ClassPathResource("ds-object.xml");
    dsObjectElement = DOMUtils.inputStreamToDocument(dsObjectResource.getInputStream()).getDocumentElement();

    xqp = XadesQualifyingProperties.createXadesQualifyingProperties(dsObjectElement);
    Assert.assertNotNull(xqp.getSigningCertificateDigest());
    Assert.assertNotNull(xqp.getSigningTime());
  }

  @Test
  public void testAssignSignaturePolicy() throws Exception {
    XadesQualifyingProperties xqp = XadesQualifyingProperties.createXadesQualifyingProperties();
    xqp.setSignaturePolicy("1.2.3.4.5");
    Assert.assertNotNull(xqp.getSignaturePolicyIdentifier());
    Assert.assertEquals("1.2.3.4.5",
      xqp.getSignaturePolicyIdentifier().getSignaturePolicyId().getSigPolicyId()
        .getIdentifier().getValue());
  }
  
  @Test
  public void testAssignSignaturePolicyToObject() throws Exception {
    Resource dsObjectResource = new ClassPathResource("ds-object.xml");
    Element dsObjectElement = DOMUtils.inputStreamToDocument(dsObjectResource.getInputStream()).getDocumentElement();

    XadesQualifyingProperties xqp = XadesQualifyingProperties.createXadesQualifyingProperties(dsObjectElement);
    
    xqp.setSignaturePolicy("1.2.3.4.5");
    Assert.assertNotNull(xqp.getSignaturePolicyIdentifier());
    Assert.assertEquals("1.2.3.4.5",
      xqp.getSignaturePolicyIdentifier().getSignaturePolicyId().getSigPolicyId()
        .getIdentifier().getValue());
    
    // Assert that updating works
    Element element = xqp.getAdesElement();
    XadesQualifyingProperties xqp2 = XadesQualifyingProperties.createXadesQualifyingProperties(element);
    Assert.assertNotNull(xqp2.getSignaturePolicyIdentifier());
    Assert.assertEquals("1.2.3.4.5",
      xqp2.getSignaturePolicyIdentifier().getSignaturePolicyId().getSigPolicyId()
        .getIdentifier().getValue());
  }

}
