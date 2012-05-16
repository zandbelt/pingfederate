package com.yubico.client.v2;

/* 	Copyright (c) 2011, Simon Buckle.  All rights reserved.
	Copyright (c) 2012, Yubico AB. All rights reserved.

	Redistribution and use in source and binary forms, with or without
	modification, are permitted provided that the following conditions
	are met:

	* Redistributions of source code must retain the above copyright
	notice, this list of conditions and the following disclaimer.

	* Redistributions in binary form must reproduce the above copyright
	notice, this list of conditions and the following
	disclaimer in the documentation and/or other materials provided
	with the distribution.

	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
	CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
	INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
	MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
	DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS
	BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
	EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
	TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
	DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
	ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
	TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
	THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
	SUCH DAMAGE.

	Written by Simon Buckle <simon@webteq.eu>, September 2011.
*/
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import com.yubico.client.v2.exceptions.YubicoReplayedRequestException;
import com.yubico.client.v2.exceptions.YubicoValidationException;
import com.yubico.client.v2.impl.YubicoResponseImpl;

/**
 * Fires off a number of validation requests to each specified URL 
 * in parallel.
 * 
 * @author Simon Buckle <simon@webteq.eu>
 */
public class YubicoValidationService {
	/**
	 * Fires off a validation request to each url in the list, returning the first one
	 * that is not {@link YubicoResponseStatus#REPLAYED_REQUEST}
	 * 
	 * @param urls a list of validation urls to be contacted
	 * @return {@link YubicoResponse} object from the first server response that's not
	 * {@link YubicoResponseStatus#REPLAYED_REQUEST}
	 * @throws YubicoValidationException if validation fails on all urls
	 */
	public YubicoResponse fetch(List<String> urls) throws YubicoValidationException {
		ExecutorService pool = Executors.newFixedThreadPool(urls.size());
		
	    List<Callable<YubicoResponse>> tasks = new ArrayList<Callable<YubicoResponse>>();
	    for(String url : urls) {
	    	tasks.add(new VerifyTask(url));
	    }
	    YubicoResponse response = null;
		try {
			response = pool.invokeAny(tasks, 1L, TimeUnit.MINUTES);
		} catch (ExecutionException e) {
			throw new YubicoValidationException("Exception while executing validation.", e.getCause());
		} catch (TimeoutException e) {
			throw new YubicoValidationException("Timeout waiting for validation server response.", e);
		} catch (InterruptedException e) {
			throw new YubicoValidationException("Validation interrupted.", e);
		}
	    return response;
	}
	
	class VerifyTask implements Callable<YubicoResponse> {
		private final String url;
		public VerifyTask(String url) {
			this.url = url;
		}
		
		public YubicoResponse call() throws Exception {
			URL url = new URL(this.url);
			HttpURLConnection conn = (HttpURLConnection)url.openConnection();
			conn.setConnectTimeout(15000); // 15 second timeout
			conn.setReadTimeout(15000); // for both read and connect
			YubicoResponse resp = new YubicoResponseImpl(conn.getInputStream());
			// @see http://forum.yubico.com/viewtopic.php?f=3&t=701
			if (YubicoResponseStatus.REPLAYED_REQUEST.equals(resp.getStatus())) {
				throw new YubicoReplayedRequestException("Replayed request.");
			}
			return resp;
		}	
	}
}
