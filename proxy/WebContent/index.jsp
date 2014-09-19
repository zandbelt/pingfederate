<%
/***************************************************************************
 * Copyright (C) 2011-2013 Ping Identity Corporation
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
 * @Version: 3.0
 *
 * @Author: Hans Zandbelt - hzandbelt@pingidentity.com
 *
 **************************************************************************/
%>
<%@page import="java.io.BufferedWriter"%>
<%@page import="java.util.HashMap"%>
<%@page import="java.util.Map"%>
<%@page import="java.util.Date"%>
<%@page import="java.util.Properties"%>
<%@page import="java.net.URLEncoder"%>
<%@page import="java.io.OutputStreamWriter"%>
<%@page import="java.io.OutputStream"%>
<%@page import="java.io.InputStreamReader"%>
<%@page import="java.io.InputStream"%>
<%@page import="javax.net.ssl.HttpsURLConnection"%>
<%@page import="java.net.URL"%>
<%@page import="javax.servlet.http.Cookie"%>
<%@page import="org.json.simple.JSONObject" %>
<%@page import="org.json.simple.parser.JSONParser" %>
<%@page import="javax.net.ssl.X509TrustManager"%>
<%@page import="java.security.cert.CertificateException"%>
<%@page import="java.security.cert.X509Certificate"%>
<%@page import="javax.net.ssl.SSLSocketFactory"%>
<%@page import="javax.net.ssl.TrustManager"%>
<%@page import="javax.net.ssl.SSLContext"%>
<%@page import="javax.net.ssl.SSLSession"%>
<%@page import="javax.net.ssl.HostnameVerifier"%>
<%@page import="org.sourceid.saml20.adapter.state.SessionStateSupport"%> 
<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%!

/**
  * state (i.e. JSON identity attributes + timestamp that is stored in the session
  */
private static class ProxySSOSessionState {
	private JSONObject jsonObject = null;
	private Date timeStamp = null;
	public ProxySSOSessionState(JSONObject json) {
		this.jsonObject = json;
		this.timeStamp = new Date();
	}

	public JSONObject getJSONObject() {
		return this.jsonObject;
	}

	public Date getTimestamp() {
		return this.timeStamp;
	}
}

/**
 * Execute a REST call to the Reference ID adapter.
 */
public JSONObject doREST(String url, Properties p, String type, JSONObject jsonRespObj) throws Exception {

	X509TrustManager tm = null;
	HostnameVerifier hv = null;
	SSLSocketFactory socketFactory = null;
		
	if (Boolean.parseBoolean(p.getProperty("ssl.server.certificate.validation", "true")) != true) {
		tm = new X509TrustManager() {
			public void checkClientTrusted(X509Certificate[] x509Certs, String s) throws CertificateException {}
			public void checkServerTrusted(X509Certificate[] x509Certs, String s) throws CertificateException {}
			public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
		};
		SSLContext sslContext = SSLContext.getInstance("TLS");
		sslContext.init(null, new TrustManager[] {tm}, null);
		socketFactory = sslContext.getSocketFactory();
	}
	
	URL u = new URL(url);
	HttpsURLConnection con = (HttpsURLConnection)u.openConnection();

	if (Boolean.parseBoolean(p.getProperty("ssl.server.certificate.validation", "true")) != true) {
		con.setSSLSocketFactory(socketFactory);
	}
	
	if (Boolean.parseBoolean(p.getProperty("ssl.hostname.verification", "true")) != true) {
		hv = new HostnameVerifier() {
			public boolean verify(String urlHostName, SSLSession session) { return true; }
		};
		con.setHostnameVerifier(hv);
	}

	con.setRequestProperty("ping.uname", p.getProperty(type + ".adapter.username"));
	con.setRequestProperty("ping.pwd", p.getProperty(type + ".adapter.password"));
	con.setRequestProperty("ping.instanceId", p.getProperty(type + ".adapter.id"));
	
	if (jsonRespObj != null) {
		con.setDoOutput(true);
		OutputStreamWriter outputStreamWriter = new OutputStreamWriter(con.getOutputStream(), "UTF-8");
		jsonRespObj.writeJSONString(outputStreamWriter);
		outputStreamWriter.flush();
		outputStreamWriter.close();
	}

	InputStream ins = con.getInputStream();
	InputStreamReader isr = new InputStreamReader(ins);
	JSONParser parser = new JSONParser();
		
	return (JSONObject)parser.parse(isr);
}

/**
 * Pickup attributes from PingFederate using the Agentless protocol.
 */ 
public JSONObject doPickup(Properties p, String role, HttpServletRequest request, HttpServletResponse response, SessionStateSupport sessionStateSupport) throws Exception {
	String pickupUrl = p.getProperty("pf.base.url") + "/ext/ref/pickup?REF=" + URLEncoder.encode(request.getParameter("REF"), "UTF-8");
	JSONObject jsonObject = doREST(pickupUrl, p, role, null);
	sessionStateSupport.setAttribute("state", new ProxySSOSessionState(jsonObject), request, response, false);
	return jsonObject;
}

/**
 * Drop-off attributes to PingFederate using the Agentless protocol.
 */ 
public String doDropoff(Properties p, String role, HttpServletRequest request, HttpServletResponse response, SessionStateSupport sessionStateSupport)  throws Exception {
	String dropoffUrl = p.getProperty("pf.base.url") + "/ext/ref/dropoff";	
	ProxySSOSessionState state = (ProxySSOSessionState)sessionStateSupport.getAttribute("state", request, response);
	JSONObject jsonObject = doREST(dropoffUrl, p, role, state.getJSONObject());	
	return (String)jsonObject.get("REF");
}

/**
 * send off the browser to the resumePath to PingFederate
 */
public void doResume(Properties p, String resumePath, HttpServletResponse response, String ref)  throws Exception {
	String strReturnUrl = p.getProperty("pf.base.url") + resumePath + "?REF=" + URLEncoder.encode(ref, "UTF-8");
	response.sendRedirect(strReturnUrl);	
}

%>
<%
	String cmdValue = request.getParameter("cmd");

	// for storing stuff in the session information that is shared in a cluster
	SessionStateSupport sessionStateSupport = new SessionStateSupport();

	InputStream stream = application.getResourceAsStream("/proxy.properties");
	Properties p = new Properties();
	p.load(stream);
	long sessionTimeout = Long.valueOf(p.getProperty("session.timeout", "0"));
	
	if (cmdValue == null) {

		// start IDP-initiated-SSO
		doPickup(p, "sp", request, response, sessionStateSupport);

		String strReturnUrl = p.getProperty("pf.base.url");
		String idpAdapterId = (request.getParameter("IdpAdapterId") != null) ? request.getParameter("IdpAdapterId") : p.getProperty("idp.adapter.id");
		strReturnUrl += "/idp/startSSO.ping?IdpAdapterId=" +  URLEncoder.encode(idpAdapterId, "UTF-8");
		if (request.getParameter("PartnerSpId") != null) strReturnUrl += "&PartnerSpId=" + URLEncoder.encode(request.getParameter("PartnerSpId"), "UTF-8");
		if (request.getParameter("TargetResource") != null) strReturnUrl += "&TargetResource=" + URLEncoder.encode(request.getParameter("TargetResource"), "UTF-8");

		response.sendRedirect(strReturnUrl);

	} else if (cmdValue.equals("idp-sso")) {

		ProxySSOSessionState state = (ProxySSOSessionState)sessionStateSupport.getAttribute("state", request, response);
		if ( (state != null) && (new Date().before(new Date(state.getTimestamp().getTime() + sessionTimeout * 1000)))) {

			// continue IDP initiated SSO
			doResume(p, request.getParameter("resumePath"), response, doDropoff(p, "idp", request, response, sessionStateSupport));

		} else {
			// this is an SP request to the IDP adapter that we forward to the IDP Discovery page for the SP adapter

			// assemble the URL to CDC endpoint and send the browser off
			String startSSOUrl = p.getProperty("pf.base.url");

			startSSOUrl += (request.getParameter("startsso") != null) ? request.getParameter("startsso") : p.getProperty("pf.start.sso.path", "/sp/cdcstartSSO.ping");
			startSSOUrl += (startSSOUrl.indexOf("?") > -1) ? "&" : "?";
			startSSOUrl += "SpSessionAuthnAdapterId=" +  URLEncoder.encode(p.getProperty("sp.adapter.id"), "UTF-8");
			// kick off url: https://proxy:9031/pf/adapter2adapter.ping?SpSessionAuthnAdapterId=spadapter&IdpAdapterId=proxyidpadapter2
			// proxyidpadapter2 adapter auth service url: https://proxy:9031/proxy/?cmd=idp-sso&startsso=%2Fpf%2Fadapter2adapter.ping&IdpAdapterId=facebook
			if (request.getParameter("IdpAdapterId") != null) {
				startSSOUrl += "&IdpAdapterId=" + URLEncoder.encode(request.getParameter("IdpAdapterId"), "UTF-8");
			}
			if (request.getParameter("PartnerIdpId") != null) {
				startSSOUrl += "&PartnerIdpId=" + URLEncoder.encode(request.getParameter("PartnerIdpId"), "UTF-8");
			}
			String targetResource = p.getProperty("pf.base.url") + p.getProperty("proxy.path");
			targetResource += "?cmd=idp-sso-resume&resumePath=" + URLEncoder.encode(request.getParameter("resumePath"), "UTF-8");
			startSSOUrl += "&TargetResource=" + URLEncoder.encode(targetResource, "UTF-8");
			response.sendRedirect(startSSOUrl);

		}

	} else if (cmdValue.equals("idp-sso-resume")) {
		// this is a response from the IDP to the SP adapter that we forward to the SP through the IDP adapter

		doPickup(p, "sp", request, response, sessionStateSupport);
		doResume(p, request.getParameter("resumePath"), response, doDropoff(p, "idp", request, response, sessionStateSupport));

	} else if (cmdValue.equals("sp-slo")) {

		// this is a logout request from the IDP through the SP adapter
		JSONObject jsonObj = doPickup(p, "sp", request, response, sessionStateSupport);

		if (sessionStateSupport.getAttribute("dummy", request, response) != null) {

			// SLO was already initiated by peer leg so just resume
			sessionStateSupport.removeAttribute("dummy", request, response);
			// send off the browser to the resumePath, ie. to the IDP			
			doResume(p, (String)jsonObj.get("resumePath"), response, request.getParameter("REF"));

		} else {

			sessionStateSupport.setAttribute("dummy", "", request, response, false);
			// assemble the URL to SLO endpoint and send the browser off to the SP through the IDP adapter
			String startSLOUrl = p.getProperty("pf.base.url") + "/idp/startSLO.ping";
			String targetResource = p.getProperty("pf.base.url") + p.getProperty("proxy.path");
			targetResource += "?cmd=slo-resume&resumePath=" + URLEncoder.encode((String)jsonObj.get("resumePath"), "UTF-8");
			targetResource += "&REF=" + URLEncoder.encode(request.getParameter("REF"), "UTF-8");
			startSLOUrl += "?TargetResource=" + URLEncoder.encode(targetResource, "UTF-8");
			response.sendRedirect(startSLOUrl);

		}

	} else if (cmdValue.equals("idp-slo")) {

		// this is a logout request from the SP through the IDP adapter
		JSONObject jsonObj = doPickup(p, "idp", request, response, sessionStateSupport);

		if (sessionStateSupport.getAttribute("dummy", request, response) != null) {

			// SLO was already initiated by peer leg so just resume
			sessionStateSupport.removeAttribute("dummy", request, response);
			// send off the browser to the resumePath, ie. to the SP
			doResume(p, (String)jsonObj.get("resumePath"), response, request.getParameter("REF"));

		} else {

			sessionStateSupport.setAttribute("dummy", "", request, response, false);
			// assemble the URL to SLO endpoint and send the browser off to the IDP through the SP adapter
			String startSLOUrl = p.getProperty("pf.base.url");
			startSLOUrl += "/sp/startSLO.ping?SpSessionAuthnAdapterId=" +  URLEncoder.encode(p.getProperty("sp.adapter.id"), "UTF-8");
			String targetResource = p.getProperty("pf.base.url") + p.getProperty("proxy.path");
			targetResource += "?cmd=slo-resume&resumePath=" + URLEncoder.encode((String)jsonObj.get("resumePath"), "UTF-8");
			targetResource += "&REF=" + URLEncoder.encode(request.getParameter("REF"), "UTF-8");
			startSLOUrl += "&TargetResource=" + URLEncoder.encode(targetResource, "UTF-8");
			response.sendRedirect(startSLOUrl);

		}

	} else if (cmdValue.equals("slo-resume")) {

		// kill the session and send off the browser to the resumePath, ie. to the IDP/SP
		sessionStateSupport.removeAttribute("state", request, response);
		doResume(p, request.getParameter("resumePath"), response, request.getParameter("REF"));

	} else {

		response.getWriter().print("Invalid request: \"" + cmdValue + "\"");

	}
%>