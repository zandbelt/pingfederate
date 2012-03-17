<%
/***************************************************************************
 * Copyright (C) 2011 Ping Identity Corporation
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
<%@page import="java.io.BufferedWriter"%>
<%@page import="java.util.HashMap"%>
<%@page import="java.util.Map"%>
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

<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>

<%!

// TODO: - use regular JSP session object+cookie instead of our own cookie
//       - support SSO session on the proxy through this object too, configurable (yes/no, timeout) by property settings
     
public JSONObject execRESTcall(String url, Properties p, String type, JSONObject jsonRespObj) throws Exception {
	URL u = new URL(url);
	HttpsURLConnection con = (HttpsURLConnection)u.openConnection();
	
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

public String doCookieStuff(HttpServletRequest request, HttpServletResponse response, String value) throws Exception {
	String result = null;
	String cookieName = "proxy-state";
	Cookie cookies [] = request.getCookies ();
	Cookie myCookie = null;
	if (cookies != null) {
		for (int i = 0; i < cookies.length; i++) {
			if (cookies [i].getName().equals (cookieName)) {
				myCookie = cookies[i];
				break;
			}
		}
	}
	if (myCookie == null) {
		result = null;
		myCookie = new Cookie (cookieName, value);
	} else {
		result = myCookie.getValue();
		myCookie = new Cookie(cookieName,value);
		myCookie.setMaxAge(0);
	}
	response.addCookie(myCookie);
	return result;
}

%>

<%
	String cmdValue = request.getParameter("cmd");

	InputStream stream = application.getResourceAsStream("/proxy.properties");
	Properties p = new Properties();
	p.load(stream);
	
	if (cmdValue == null) {
		
		// IDP-initiated-SSO
		
		doCookieStuff(request, response, request.getParameter("REF"));

		String strReturnUrl = p.getProperty("pf.base.url");
		strReturnUrl += "/idp/startSSO.ping?IdpAdapterId=" +  URLEncoder.encode(p.getProperty("idp.adapter.id"), "UTF-8");
		if (request.getParameter("PartnerSpId") != null) strReturnUrl += "&PartnerSpId=" + URLEncoder.encode(request.getParameter("PartnerSpId"), "UTF-8");
		if (request.getParameter("TargetResource") != null) strReturnUrl += "&TargetResource=" + URLEncoder.encode(request.getParameter("TargetResource"), "UTF-8");

		response.sendRedirect(strReturnUrl);
		
	} else if (cmdValue.equals("idp-sso")) {

		String cookie = doCookieStuff(request, response, "dummy");
		if (cookie != null) {
			// continue IDP init

			// pickup the attributes from the IDP using the Agentless protocol
			String pickupUrl = p.getProperty("pf.base.url.backchannel") + "/ext/ref/pickup?REF=" + URLEncoder.encode(cookie, "UTF-8");
			JSONObject jsonRespObj = execRESTcall(pickupUrl, p, "sp", null);

			// dropoff the attributes encoded in the JSON object for SP application retrieval
			String dropoffUrl = p.getProperty("pf.base.url.backchannel") + "/ext/ref/dropoff";
			jsonRespObj = execRESTcall(dropoffUrl, p, "idp", jsonRespObj);
		
			// send off the browser to the resumePath, ie. to the SP application
			String strReturnUrl = p.getProperty("pf.base.url") + request.getParameter("resumePath") + "?REF=" + URLEncoder.encode((String)jsonRespObj.get("REF"), "UTF-8") + "&IdpAdapterId=" + URLEncoder.encode(p.getProperty("idp.adapter.id"), "UTF-8");
			response.sendRedirect(strReturnUrl);
			
		} else {
			// this is an SP request that we forward to the IDP Discovery page
			
			// assemble the URL to CDC endpoint and send the browser off
			String startCDCUrl = p.getProperty("pf.base.url");
			startCDCUrl += "/sp/cdcstartSSO.ping?SpSessionAuthnAdapterId=" +  URLEncoder.encode(p.getProperty("sp.adapter.id"), "UTF-8");
			String targetResource = p.getProperty("pf.base.url") + p.getProperty("proxy.path");
			targetResource += "?cmd=idp-sso-resume&resumePath=" + URLEncoder.encode(request.getParameter("resumePath"), "UTF-8");
			startCDCUrl += "&TargetResource=" + URLEncoder.encode(targetResource, "UTF-8");
			response.sendRedirect(startCDCUrl);
			
		}

	} else if (cmdValue.equals("idp-sso-resume")) {
		// this is a response from the IDP that we forward to the SP

		// pickup the attributes from the IDP using the Agentless protocol
		String pickupUrl = p.getProperty("pf.base.url.backchannel") + "/ext/ref/pickup?REF=" + URLEncoder.encode(request.getParameter("REF"), "UTF-8");
		JSONObject jsonRespObj = execRESTcall(pickupUrl, p, "sp", null);

		// dropoff the attributes encoded in the JSON object for SP application retrieval
		String dropoffUrl = p.getProperty("pf.base.url.backchannel") + "/ext/ref/dropoff";
		jsonRespObj = execRESTcall(dropoffUrl, p, "idp", jsonRespObj);
	
		// send off the browser to the resumePath, ie. to the SP application
		String strReturnUrl = p.getProperty("pf.base.url") + request.getParameter("resumePath") + "?REF=" + URLEncoder.encode((String)jsonRespObj.get("REF"), "UTF-8") + "&IdpAdapterId=" + URLEncoder.encode(p.getProperty("idp.adapter.id"), "UTF-8");
		response.sendRedirect(strReturnUrl);

	} else if (cmdValue.equals("sp-slo")) {
		// this is a logout request from the IDP

		// pickup the attributes including the resumePath from the IDP using the Agentless protocol
		String pickupUrl = p.getProperty("pf.base.url.backchannel") + "/ext/ref/pickup?REF=" + URLEncoder.encode(request.getParameter("REF"), "UTF-8");
		JSONObject jsonRespObj = execRESTcall(pickupUrl, p, "sp", null);
		
		if (doCookieStuff(request, response, "dummy") != null) {
			// send off the browser to the resumePath, ie. to the IDP
			String strReturnUrl = p.getProperty("pf.base.url") + (String)jsonRespObj.get("resumePath") + "?REF=" + URLEncoder.encode(request.getParameter("REF"), "UTF-8");
			response.sendRedirect(strReturnUrl);
		} else {
			// assemble the URL to SLO endpoint and send the browser off to the IDP
			String startSLOUrl = p.getProperty("pf.base.url") + "/idp/startSLO.ping";
			String targetResource = p.getProperty("pf.base.url") + p.getProperty("proxy.path");
			targetResource += "?cmd=slo-resume&resumePath=" + URLEncoder.encode((String)jsonRespObj.get("resumePath"), "UTF-8");
			targetResource += "&REF=" + URLEncoder.encode(request.getParameter("REF"), "UTF-8");
			startSLOUrl += "?TargetResource=" + URLEncoder.encode(targetResource, "UTF-8");
			response.sendRedirect(startSLOUrl);
		}
		
	} else if (cmdValue.equals("idp-slo")) {
		// this is a logout request from the SP

		// pickup the attributes including the resumePath from the SP using the Agentless protocol
		String pickupUrl = p.getProperty("pf.base.url.backchannel") + "/ext/ref/pickup?REF=" + URLEncoder.encode(request.getParameter("REF"), "UTF-8");
		JSONObject jsonRespObj = execRESTcall(pickupUrl, p, "idp", null);
		
		if (doCookieStuff(request, response, "dummy") != null) {
			// send off the browser to the resumePath, ie. to the SP
			String strReturnUrl = p.getProperty("pf.base.url") + (String)jsonRespObj.get("resumePath") + "?REF=" + URLEncoder.encode(request.getParameter("REF"), "UTF-8");
			response.sendRedirect(strReturnUrl);
		} else {
			// assemble the URL to SLO endpoint and send the browser off to the SP
			String startSLOUrl = p.getProperty("pf.base.url");
			startSLOUrl += "/sp/startSLO.ping?SpSessionAuthnAdapterId=" +  URLEncoder.encode(p.getProperty("sp.adapter.id"), "UTF-8");
			String targetResource = p.getProperty("pf.base.url") + p.getProperty("proxy.path");
			targetResource += "?cmd=slo-resume&resumePath=" + URLEncoder.encode((String)jsonRespObj.get("resumePath"), "UTF-8");
			targetResource += "&REF=" + URLEncoder.encode(request.getParameter("REF"), "UTF-8");
			startSLOUrl += "&TargetResource=" + URLEncoder.encode(targetResource, "UTF-8");
			response.sendRedirect(startSLOUrl);
		}
	
	} else if (cmdValue.equals("slo-resume")) {

		// send off the browser to the resumePath, ie. to the IDP/SP
		String strReturnUrl = p.getProperty("pf.base.url") + request.getParameter("resumePath") + "?REF=" + request.getParameter("REF");
		response.sendRedirect(strReturnUrl);
		
	} else {

		response.getWriter().print("Invalid request: \"" + cmdValue + "\"");

	}
%>
