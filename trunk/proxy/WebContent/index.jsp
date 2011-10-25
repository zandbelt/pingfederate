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

<%
	InputStream stream = application.getResourceAsStream("/proxy.properties");
	Properties p = new Properties();
	p.load(stream);
	
	String refValue = request.getParameter("REF");

	if (refValue == null) {
		// this is an SP request that we forward to the IDP Discovery page
		
		// store the resumePath in a cookie because we need it on our way back
		Cookie cookie = new Cookie ("resumePath", request.getParameter("resumePath"));
		response.addCookie(cookie);
		
		// assemble the URL to CDC endpoint and send the browser off
		String startCDCUrl = p.getProperty("pf.base.url") + "/sp/cdcstartSSO.ping?SpSessionAuthnAdapterId=" +  URLEncoder.encode(p.getProperty("sp.adapter.id"), "UTF-8") + "&TargetResource=" + URLEncoder.encode(p.getProperty("pf.base.url") + p.getProperty("proxy.path"), "UTF-8");
		response.sendRedirect(startCDCUrl);
	} else {
		// this is a response from the IDP that we forward to the SP
		URL myurl;
		HttpsURLConnection con;
		
		// pickup the attributes from the IDP using the Agentless protocol
		String pickupUrl = p.getProperty("pf.base.url") + "/ext/ref/pickup?REF=" + URLEncoder.encode(refValue, "UTF-8");
		myurl = new URL(pickupUrl);		
		con = (HttpsURLConnection)myurl.openConnection();
		con.setRequestProperty("ping.uname", p.getProperty("sp.adapter.username"));
		con.setRequestProperty("ping.pwd", p.getProperty("sp.adapter.password"));
		con.setRequestProperty("ping.instanceId", p.getProperty("sp.adapter.id"));
		InputStream ins = con.getInputStream();
		InputStreamReader isr = new InputStreamReader(ins);
		JSONParser parser = new JSONParser();
		JSONObject jsonRespObj = (JSONObject)parser.parse(isr);

		// dropoff the attributes encoded in the JSON object for SP application retrieval
		String dropoffUrl = p.getProperty("pf.base.url") + "/ext/ref/dropoff";
		myurl = new URL(dropoffUrl);		
		con = (HttpsURLConnection)myurl.openConnection();
		con.setRequestProperty("ping.uname", p.getProperty("idp.adapter.username"));
		con.setRequestProperty("ping.pwd", p.getProperty("idp.adapter.password"));
		con.setRequestProperty("ping.instanceId", p.getProperty("idp.adapter.id"));
		con.setDoOutput(true);
		OutputStreamWriter outputStreamWriter = new OutputStreamWriter(con.getOutputStream(), "UTF-8");
		jsonRespObj.writeJSONString(outputStreamWriter);
		outputStreamWriter.flush();
		outputStreamWriter.close();
		
		// read the response from PingFederate to obtain a REF identifier
		ins = con.getInputStream();
		isr = new InputStreamReader(ins, "UTF-8");
		parser = new JSONParser();
		jsonRespObj = (JSONObject)parser.parse(isr);
		refValue = (String)jsonRespObj.get("REF");

		// restore the resumePath that we saved on our way in
		Cookie cookies [] = request.getCookies ();
		Cookie myCookie = null;
		for (int i = 0; i < cookies.length; i++) {
			if (cookies [i].getName().equals("resumePath")) {
				myCookie = cookies[i];
				break;
			}
		}
		
		// send off the browser to the resumePath, ie. to the SP application
		String strReturnUrl = p.getProperty("pf.base.url") + myCookie.getValue() + "?REF=" + URLEncoder.encode(refValue, "UTF-8") + "&IdpAdapterId=" + URLEncoder.encode(p.getProperty("idp.adapter.id"), "UTF-8");
		response.sendRedirect(strReturnUrl);		
	}
%>