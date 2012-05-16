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
