<%
/***************************************************************************
 * Copyright (C) 2012 Ping Identity Corporation
 * All rights reserved.
 *
 * The contents of this file are the property of Ping Identity Corporation.
 * For further information please contact:
 *
 *      Ping Identity Corporation
 *      1099 18th St Suite 2950
 *      Denver, CO 80202
 *      303.468.2900
 *      http://www.pingidentity.com
 *
 * DISCLAIMER OF WARRANTIES:
 *
 * THE SOFTWARE PROVIDED HEREUNDER IS PROVIDED ON AN "AS IS" BASIS, WITHOUT
 * ANY WARRANTIES OR REPRESENTATIONS EXPRESS, IMPLIED OR STATUTORY; INCLUDING,
 * WITHOUT LIMITATION, WARRANTIES OF QUALITY, PERFORMANCE, NONINFRINGEMENT,
 * MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.  NOR ARE THERE ANY
 * WARRANTIES CREATED BY A COURSE OR DEALING, COURSE OF PERFORMANCE OR TRADE
 * USAGE.  FURTHERMORE, THERE ARE NO WARRANTIES THAT THE SOFTWARE WILL MEET
 * YOUR NEEDS OR BE FREE FROM ERRORS, OR THAT THE OPERATION OF THE SOFTWARE
 * WILL BE UNINTERRUPTED.  IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 **************************************************************************/
%>
<%--

  Intercept an outgoing AuthnRequest using the Redirect binding on the SP,
  adapt it (abusing RequestedAuthnCtx) and relay it to the actual IDP.

  Configurable modifications include:
  - ProviderName attribute
  - AttributeConsumingServiceIndex attribute
  - RequestedAuthnCtx value
  (and the Destination, which needs to be overwritten anyway)
  
  Host this script on your PingFederate SP instance, eg. in quickstart-app-sp.war/
  Modify the IDP SSO URL for the Redirect binding to point to this JSP
  Redirect:	https://localhost:9031/quickstart-app-sp/authrequest-relay.jsp

  Adaptation settings are read from the file "default.properties" but they can
  be specified on-the fly by the application via (ab)using the startSSO parameter
  RequestedAuthnCtx to point to (the basename of) a properties file that specifies
  settings for adaptation.
  Eg. /sp/startSSO?[<name>=<value>]&RequestedAuthnCtx=file%3A%2F%2Fpartner.properties%3Fklaas%3Djan%26provider.name%3Dhans
  will read settings from partner.properties and override the "klaas" and "provider.name" properties
  with those specified in the "URL-like" value
  (=urlencoded: file:///partner.properties?klaas=jan&provider.name=Hans)
    
  TODO:
	- it would be more elegant to use TargetResource if that could be passed transparently into
	  RelayState and disable checks on that; that may be possible with PF >= 6.6 (?)
    - support POST binding (ie. without XML signatures..?)
	
--%>
<%@ page language="java" contentType="text/html;charset=UTF-8" pageEncoding="UTF-8"%>

<%@page import="java.net.URLEncoder"%>
<%@page import="java.io.InputStream"%>
<%@page import="java.util.Properties"%>
<%@page import="java.net.URLDecoder"%>
<%@page import="java.net.URL"%>

<%@page import="org.sourceid.saml20.domain.mgmt.MgmtFactory"%>
<%@page import="org.sourceid.saml20.domain.mgmt.PkCertAndConnectionCertManager"%>
<%@page import="org.sourceid.saml20.xmlbinding.protocol.AuthnRequestType"%>
<%@page import="org.sourceid.saml20.xmlbinding.protocol.AuthnRequestDocument"%>
<%@page import="org.sourceid.saml20.xmlbinding.protocol.RequestedAuthnContextType"%>
<%@page import="org.sourceid.common.dsig.SignatureStatus"%>
<%@page import="org.sourceid.common.dsig.QueryStringSignatureUtil"%>
<%@page import="com.pingidentity.crypto.PkCert"%>
<%
	
	// get the SAMLRequest and RelayState from the HTTP GET request
	org.sourceid.saml20.util.Encoder encoder = new org.sourceid.saml20.util.Encoder();
	String samlRequest = encoder.decodeSAMLMessage(request.getParameter("SAMLRequest"));
	String relayState = request.getParameter("RelayState");

	// parse the AuthnRequest into an XML object
	AuthnRequestDocument authnRequestDocument = AuthnRequestDocument.Factory.parse(samlRequest);
	AuthnRequestType authnRequestType = authnRequestDocument.getAuthnRequest();
	
	String propsFilename = "file:///default.properties";
	if (authnRequestType.isSetRequestedAuthnContext()) {
		try {
			propsFilename = authnRequestType.getRequestedAuthnContext().getAuthnContextClassRefArray(0);
		} catch (IndexOutOfBoundsException e) {
		}
		authnRequestType.unsetRequestedAuthnContext();
	}

	URL u = new URL(propsFilename);

	//InputStream stream = application.getResourceAsStream("/" + propsFilename + ".properties");
	InputStream stream = application.getResourceAsStream(u.getPath());
	Properties p = new Properties();
	p.load(stream);

	String q = u.getQuery();
	// override with properties from query
	if (q != null) {
		for (String param : q.split("&")) {
			String pair[] = param.split("=");
			p.setProperty(URLDecoder.decode(pair[0], "UTF-8"), URLDecoder.decode(pair[1], "UTF-8"));
	    }
	}

	// this URL can be hard-configured because this script is specific for an IDP
	// it now points to the local PF IDP instance for testing purposes
	String ssoUrl = p.getProperty("sso.url");

	String providerName = p.getProperty("provider.name");
	// set the ProviderName element in the AuthnRequest
	if (providerName != null) {
		authnRequestType.setProviderName(providerName);
	}

	// optionally set AttributeConsumingServiceIndex
	String attrConsumingServiceIndex = p.getProperty("attribute.consuming.service.index");
	if (attrConsumingServiceIndex != null) {
		authnRequestType.setAttributeConsumingServiceIndex(Integer.parseInt(attrConsumingServiceIndex));
	}

	// overwrite destination
	authnRequestType.setDestination(ssoUrl);

	// set the requested authn context
	String requestedAuthnContext = p.getProperty("requested.authn.context");
	if (requestedAuthnContext != null) {
		RequestedAuthnContextType reqAuthnCtx = authnRequestType.addNewRequestedAuthnContext();
        reqAuthnCtx.addAuthnContextClassRef(requestedAuthnContext);
	}

	// rebuild the SSO request by encoding the SAML AuthnRequest and set the query params
	StringBuilder sb = new StringBuilder("SAMLRequest");
	String msg = authnRequestDocument.xmlText();
	String encodedMsg = URLEncoder.encode(encoder.encodeSAMLMessage(msg), "UTF-8");
	sb.append("=").append(encodedMsg);
	if (relayState != null) {
		sb.append("&").append("RelayState").append("=").append(URLEncoder.encode(relayState, "UTF-8"));
	}

	// get the signing keyAlias from the server/default/data/sourceid-saml2-metadata.xml
	// for this IDP connection
	String keyAlias = p.getProperty("signing.key.alias");
	String signingAlgorithm = p.getProperty("signing.key.algorithm", "http://www.w3.org/2000/09/xmldsig#rsa-sha1");
		
	if (keyAlias != null) {
        PkCertAndConnectionCertManager dsigPkCertManager = (PkCertAndConnectionCertManager)MgmtFactory.getDsigPkCertManager();
        PkCert pkCert = dsigPkCertManager.getPkCert(keyAlias);
		
        // if we are going to sign, the incoming request must be signed too, so verify this (because of AssertionConsumerURL etc..)
		SignatureStatus signatureStatus = QueryStringSignatureUtil.verifyQuerySignature(request.getQueryString(), pkCert.getX509Certificate().getPublicKey());
		if (signatureStatus != SignatureStatus.VALID) throw new Exception("signature invalid");
		
        QueryStringSignatureUtil.SignedQuery signedQuery = QueryStringSignatureUtil.signQuery(sb.toString(), pkCert.getPrivateKey(), signingAlgorithm);
	    sb = new StringBuilder(signedQuery.getSignedQueryString());
	}

	// send the SAMLRequest through Redirect binding, now to the actual IDP SSO endpoint
	response.sendRedirect(ssoUrl + "?" + sb.toString());
%>
