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
package se.idsec.signservice.integration.app.controller;

import java.util.Base64;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/signed")
public class SignedDocumentController {
  
  private static final byte[] NO_SESSION =
      "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><Message>No active session exists</Message>".getBytes();

  @GetMapping(produces = { MediaType.APPLICATION_XML_VALUE, MediaType.APPLICATION_PDF_VALUE })
  public HttpEntity<byte[]> displaySignedDocument(HttpServletRequest request) {
    
    HttpSession session = request.getSession();
    String msg = (String) session.getAttribute("signedDocument");
    byte[] contents;
    if (msg != null) {
      contents = Base64.getDecoder().decode(msg);
    }
    else {
      contents = NO_SESSION;
    }
    
    HttpHeaders header = new HttpHeaders();
    
    String msgType = (String) session.getAttribute("signedDocumentType");
    if ("application/pdf".equals(msgType)) {
      header.setContentType(MediaType.APPLICATION_PDF);
    }
    else {
      header.setContentType(MediaType.APPLICATION_XML);
    }
    header.setContentLength(contents.length);
    
    return new HttpEntity<byte[]>(contents, header);
  }

}
