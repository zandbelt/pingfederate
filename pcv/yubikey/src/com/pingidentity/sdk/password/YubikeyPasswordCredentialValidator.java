/**
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
 * 
 * This class adds basic support to PingFederate > 6.6 for authenticating users with a
 * Yubikey (http://www.yubico.com/yubikey), through a Password Credential Validator (PCV).
 * 
 * This PCV would be combined with a datastore lookup where the resulting "username"
 * attribute that now contains the Yubikey identifier would be matched against a user
 * record.
 * 
 * TBD: detailed error handling
 * 
 * Author: Hans Zandbelt - hzandbelt@pingidentity.com
 * 
 **************************************************************************/

package com.pingidentity.sdk.password;

import java.util.Collections;

import org.sourceid.saml20.adapter.conf.Configuration;
import org.sourceid.saml20.adapter.conf.Row;
import org.sourceid.saml20.adapter.conf.Table;
import org.sourceid.saml20.adapter.gui.FieldDescriptor;
import org.sourceid.saml20.adapter.gui.TableDescriptor;
import org.sourceid.saml20.adapter.gui.TextFieldDescriptor;
import org.sourceid.saml20.adapter.gui.validation.impl.RequiredFieldValidator;
import org.sourceid.util.log.AttributeMap;

import com.pingidentity.sdk.GuiConfigDescriptor;
import com.pingidentity.sdk.PluginDescriptor;
import com.yubico.client.v2.YubicoClient;
import com.yubico.client.v2.YubicoResponse;
import com.yubico.client.v2.YubicoResponseStatus;

public class YubikeyPasswordCredentialValidator implements
		PasswordCredentialValidator {

	private Configuration configuration = null;
	private PluginDescriptor descriptor;

	public YubikeyPasswordCredentialValidator() {
		GuiConfigDescriptor guiDescriptor = new GuiConfigDescriptor();
		addConfigurationFields(guiDescriptor);
		this.descriptor = new PluginDescriptor(
				"Yubikey Password Credential Validator "
						+ getVersion(), this, guiDescriptor);
		this.descriptor.setAttributeContactSet(Collections
				.singleton("username"));
		this.descriptor.setSupportsExtendedContract(false);
	}

	public void configure(Configuration paramConfiguration) {
		this.configuration = paramConfiguration;		
	}

	public PluginDescriptor getPluginDescriptor() {
		return this.descriptor;
	}

	public AttributeMap processPasswordCredential(String username, String otp) {
		AttributeMap attrs = null;
		int authId = this.configuration.getIntFieldValue("Client ID");
/*
		String pAPISecret = this.configuration.getFieldValue("API Secret");
*/		
		try {
			YubicoClient yc = YubicoClient.getClient(authId);

		    Table table = configuration.getTable("Validation Server URLs");
		    if ( (table != null) && (table.getRows().size() > 0) ) {
			    String[] urls = new String[table.getRows().size()];
		    	int i = 0;
		    	for (Row row : table.getRows()) {
		    		urls[i] = row.getFieldValue("URL");
		    		i++;
		    	}
				yc.setWsapiUrls(urls);
		    }
		    
			YubicoResponse response = yc.verify(otp);
	        if (response!=null && response.getStatus() == YubicoResponseStatus.OK) {
				attrs = new AttributeMap();
				attrs.put("username", otp.substring(0, otp.length() - 32));
	        }
		} catch (Exception e) {
		}

		return attrs;
	}

	private void addConfigurationFields(GuiConfigDescriptor gui) {

	    TableDescriptor table = new TableDescriptor("Validation Server URLs", "A table of Yubikey Validation Server URLs (leave empty for defaults).");
	    FieldDescriptor url = new TextFieldDescriptor("URL", "A URL to a Yubikey Validation Server");
	    url.addValidator(new RequiredFieldValidator());
	    table.addRowField(url);
	    gui.addTable(table);
	    
		FieldDescriptor clientId = new TextFieldDescriptor("Client ID",
				"The client identifier that you have registered with your Yubikey Validation Server");
		clientId.addValidator(new RequiredFieldValidator());
		gui.addField(clientId);
/*
		FieldDescriptor apiKey = new TextFieldDescriptor("API Key",
				"The API key that authenticates your client against the Yubikey Validation Server");
		apiKey.addValidator(new RequiredFieldValidator());
		gui.addField(apiKey);
*/
	}

	private String getVersion() {
		return "1.0";
	}
}
