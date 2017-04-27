/***************************************************************************
 * Copyright (C) 2013 Ping Identity Corporation
 * All rights reserved.
 *
 * The contents of this file are the property of Ping Identity Corporation.
 * You may not copy or use this file, in either source code or executable
 * form, except in compliance with terms set by Ping Identity Corporation.
 * For further information please contact:
 *
 *      Ping Identity Corporation
 *      1001 17th Street Suite 100
 *      Denver, CO 80202
 *      303.468.2900
 *      http://www.pingidentity.com
 *
 **************************************************************************/
package com.pingidentity.identitystoreprovisioner;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Random;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.sourceid.saml20.adapter.attribute.AttrValueSupport;
import org.sourceid.saml20.adapter.attribute.AttributeValue;
import org.sourceid.saml20.adapter.conf.Configuration;
import org.sourceid.saml20.adapter.gui.RadioGroupFieldDescriptor;
import org.sourceid.saml20.adapter.gui.LdapDatastoreFieldDescriptor;
import org.sourceid.saml20.adapter.gui.TextFieldDescriptor;
import org.sourceid.util.log.AttributeMap;

import com.pingidentity.sdk.GuiConfigDescriptor;
import com.pingidentity.sdk.IdentityStoreProvisionerDescriptor;
import com.pingidentity.sdk.PluginDescriptor;
import com.pingidentity.sdk.provision.Constants;
import com.pingidentity.sdk.provision.IdentityStoreUserProvisioner;
import com.pingidentity.sdk.provision.exception.BadRequestException;
import com.pingidentity.sdk.provision.exception.ConflictException;
import com.pingidentity.sdk.provision.exception.IdentityStoreException;
import com.pingidentity.sdk.provision.exception.NotFoundException;
import com.pingidentity.sdk.provision.users.request.CreateUserRequestContext;
import com.pingidentity.sdk.provision.users.request.DeleteUserRequestContext;
import com.pingidentity.sdk.provision.users.request.ReadUserRequestContext;
import com.pingidentity.sdk.provision.users.request.UpdateUserRequestContext;
import com.pingidentity.sdk.provision.users.response.UserResponseContextImpl;

import com.pingidentity.access.DataSourceAccessor;
import org.sourceid.saml20.domain.datasource.info.LdapInfo;
import com.pingidentity.helper.LdapHelper;

import com.unboundid.util.StaticUtils;


public class LdapProvisioner implements IdentityStoreUserProvisioner {

    private static final Log log = LogFactory.getLog(LdapProvisioner.class);

    // Plugin static String values.
    private static final String PLUGIN_TYPE = "LDAP Identity Store Provisioner";
    private static final String PLUGIN_VERSION = "1.0";
    private static final String PLUGIN_DESCRIPTION = "This Identity Store Provisioner provides a means of persisting users to a custom data source.";

    private static final String LDAP_DATA_STORE_NAME = "LDAP data store";
    private static final String LDAP_DATA_STORE_DESCRIPTION = "Select the LDAP data store to provision users into.";
    
    private static final String LDAP_BASE_DN_NAME = "LDAP container to provision";
    private static final String LDAP_BASE_DN_DESCRIPTION = "Select the LDAP container to provision users into.";

    private static final String RADIO_BUTTON_NAME = "Delete user behavior";
    private static final String RADIO_BUTTON_DESCRIPTION = "Select whether a user should be disabled or permanently deleted when a delete request is sent to the plugin";

    // Base Dn to provision to
    // AttributeName to use for OU?
    // Attribute list ? (get from context?)
    
    // Constants for delete/disable radio options
    private static final String DELETE_USER = "Permanently Delete User";
    private static final String DISABLE_USER = "Disable User";

    // The active attribute defines whether the user in this implementation is enabled or disabled
    private static final String ACTIVE = "accountActive";

    // The username is a required core contract attribute that must be fulfilled at runtime.
    private static final String USERNAME = "username";

    // Static "User not found" exception message.
    private static final String USER_NOT_FOUND = "User not found";

    // The PluginDescriptor that defines this plugin.
    private final PluginDescriptor descriptor;

    // Runtime value of the delete/disable radio option in the plugin Admin UI.
    private boolean permanentlyDeleteUser;

    private LdapHelper ldapHelper;
    private String BaseDn;
    private String[] ldapAttributeList;

    /**
     * Creates a new sample identity store provisioner and initialize its GUI descriptor.
     */
    public LdapProvisioner()
    {
        super();

        // Construct a GuiConfigDescriptor to hold custom gui web controls
        GuiConfigDescriptor guiDescriptor = new GuiConfigDescriptor();

        // Add a description.
        guiDescriptor.setDescription(PLUGIN_DESCRIPTION);
        
        LdapDatastoreFieldDescriptor chooseLdapDatastoreDescriptor = new LdapDatastoreFieldDescriptor(LDAP_DATA_STORE_NAME, LDAP_DATA_STORE_DESCRIPTION);
        guiDescriptor.addField(chooseLdapDatastoreDescriptor);

        TextFieldDescriptor baseDnDescriptor = new TextFieldDescriptor(LDAP_BASE_DN_NAME, LDAP_BASE_DN_DESCRIPTION);
        guiDescriptor.addField(baseDnDescriptor);
        
        // Define a radio option for delete/disable.
        String[] options = {DISABLE_USER, DELETE_USER};

        // Define the disable/delete radio button controls displayed
        // in the Identity Store Plugin Admin UI for this plugin.
        RadioGroupFieldDescriptor disableOrDeleteRadioButtonDescriptor = new RadioGroupFieldDescriptor(
                                                                                                       RADIO_BUTTON_NAME,
                                                                                                       RADIO_BUTTON_DESCRIPTION,
                                                                                                       options);

        // Set the default value for the radio option.
        disableOrDeleteRadioButtonDescriptor.setDefaultValue(DISABLE_USER);

        // Add the field to the gui descriptor object.
        guiDescriptor.addField(disableOrDeleteRadioButtonDescriptor);

        // Load the guiDescriptor into the PluginDescriptor.
        descriptor = new IdentityStoreProvisionerDescriptor(PLUGIN_TYPE, this, guiDescriptor, new HashSet<String>(),
                                                            PLUGIN_VERSION);

        // Add a collection of Strings here to define the Core Contract in this Identity Store Provisioner instance.
        descriptor.setAttributeContractSet(Collections.singleton(USERNAME));

        // Allow the contract to be extended.
        descriptor.setSupportsExtendedContract(true);
    }

    @Override
    public void configure(Configuration configuration)
    {
    	// Ldap datastore
    	String ldapDatastoreValue = configuration.getFieldValue(LDAP_DATA_STORE_NAME);
    	DataSourceAccessor dataSourceAccessor = new DataSourceAccessor();
    	LdapInfo ldapConnectionInfo = dataSourceAccessor.getLdapInfo(ldapDatastoreValue);
    	ldapHelper = new LdapHelper(ldapConnectionInfo);
    	
        // Use the RadioGroupFieldDescriptor name to get the correct fieldValue.
        String fieldValue = configuration.getFieldValue(RADIO_BUTTON_NAME);
        BaseDn = configuration.getFieldValue(LDAP_BASE_DN_NAME);

        // Register the user's selection from the Identity Store Admin UI so it can be used at runtime.
        permanentlyDeleteUser = DELETE_USER.equals(fieldValue);

        ArrayList<String> attribList = new ArrayList<String>();
        
        for (String attr : configuration.getAdditionalAttrNames()) {
        	attribList.add(attr);
        }
        
        // add these "required" fields
        if (!attribList.contains("cn")) { attribList.add("cn"); };
        if (!attribList.contains("createTimestamp")) { attribList.add("createTimestamp"); };
        if (!attribList.contains("modifyTimestamp")) { attribList.add("modifyTimestamp"); };
        
        ldapAttributeList = new String[attribList.size()];
        ldapAttributeList = attribList.toArray(ldapAttributeList);
    }

    @Override
    public PluginDescriptor getPluginDescriptor()
    {
        return descriptor;
    }

    @Override
    public UserResponseContextImpl createUser(CreateUserRequestContext createRequestCtx) throws IdentityStoreException
    {
        AttributeMap attributeMap = createRequestCtx.getUserAttributes();
        
        // verify we don't already have this user
        checkForConflict(attributeMap);

        // use email address as the id for this poc
        String id = escapeCN(attributeMap.getSingleValue(USERNAME));

        if (ldapHelper.addEntry("cn=" + id + "," + BaseDn, attributeMap)) {
            log.info("Created User: " + id);
            log.info("Entity ID: " + createRequestCtx.getEntityId());
        } else {
        	log.info("FAILED");
        }

        AttributeMap userEntry = ldapHelper.getEntry("cn=" + id, ldapAttributeList, BaseDn);
        AttributeMap returnAttributeMap = userEntryToAttributeMap(userEntry);

        // Send back the response
        return new UserResponseContextImpl(returnAttributeMap);
    }

    @Override
	public UserResponseContextImpl readUser(ReadUserRequestContext readRequestCtx) throws IdentityStoreException {
		AttributeMap attributeMap = null;

		String id = escapeCN(readRequestCtx.getUserId());
		log.info("reading user id=" + id);

		AttributeMap userEntry = ldapHelper.getEntry("cn=" + id, ldapAttributeList, BaseDn);

		//the user doesn't exist if there's no information
		if(!(userEntry.size() > 0)){
			throw new NotFoundException(USER_NOT_FOUND);
		}
		
		if (permanentlyDeleteUser || isActive(id)) {
			attributeMap = userEntryToAttributeMap(userEntry);

			// Print out some info to show the user attributes for testing.
			log.info("Read User: " + id);
			log.info("Entity ID: " + readRequestCtx.getEntityId());
			log.info("Attributes:");
			for (Map.Entry<String, AttributeValue> e : attributeMap.entrySet()) {
				log.info(String.format("%s => %s", e.getKey(), e.getValue().getValue()));
			}

		} else {
			// Since we're in "disable user on delete" mode and the user is
			// inactive (disabled) the SCIM spec says to return a 404 in this 
			// case as though the user doesn't exist.
			throw new NotFoundException(USER_NOT_FOUND);
		}

		// Send back the response
		return new UserResponseContextImpl(attributeMap);
	}

        // Send back the response
        return new UserResponseContextImpl(attributeMap);
    }

    @Override
    public UserResponseContextImpl updateUser(UpdateUserRequestContext updateRequestCtx) throws IdentityStoreException
    {
    	
    	log.debug("---[ updateUser ]------");

    	AttributeMap updatedAttributeMap = null;
        String id = escapeCN(updateRequestCtx.getUserId());

        AttributeMap userEntry = ldapHelper.getEntry("cn=" + id, ldapAttributeList, BaseDn);

        if (userEntry != null) {

            if (permanentlyDeleteUser || isActive(id)) {

                if (ldapHelper.modifyEntry("cn=" + id + "," + BaseDn, userEntry, updateRequestCtx.getUserAttributes())) {
                	userEntry = ldapHelper.getEntry("cn=" + id, ldapAttributeList, BaseDn);
                    updatedAttributeMap = userEntryToAttributeMap(userEntry);
                } else {
                	throw new BadRequestException("Error modifying user");
                }

            } else {
                // Since we're in "disable user on delete" mode and the user is inactive (disabled)
                // the SCIM spec says to return a 404 in this case as though the user doesn't exist.
                throw new NotFoundException(USER_NOT_FOUND);
            }
        } else {
            // couldn't find the user in memory
            throw new NotFoundException(USER_NOT_FOUND + ": " + id);
        }

        // Send back the response
        return new UserResponseContextImpl(updatedAttributeMap);
    }

    @Override
    public void deleteUser(DeleteUserRequestContext deleteRequestCtx) throws IdentityStoreException
    {
        String id = escapeCN(deleteRequestCtx.getUserId());
        AttributeMap userEntry = ldapHelper.getEntry("cn=" + id, ldapAttributeList, BaseDn);

        if (userEntry != null) {

            // Found an existing user - do we disable or delete?
            if (permanentlyDeleteUser) {
            	
            	ldapHelper.deleteEntry("cn=" + id + "," + BaseDn);
                log.info("Deleted User: " + id);
                log.info("Entity ID: " + deleteRequestCtx.getEntityId());
            } else {
                
            	if (isActive(id)) {
                    // we're not in permanentlyDeleteUser mode and they're active so just disable them
            		AttributeMap disabledUserEntry = new AttributeMap();
            		disabledUserEntry.putAll(userEntry);
            		disabledUserEntry.put(ACTIVE, AttrValueSupport.make(false));
            		
                    if (ldapHelper.modifyEntry("cn=" + id + "," + BaseDn, userEntry, disabledUserEntry)) {
                    	// disabled!
                    } else {
                    	throw new BadRequestException("Error modifying user");
                    }
                    
                    log.info("Disabled User: " + id);
                    log.info("Entity ID: " + deleteRequestCtx.getEntityId());
                } else {
                    // Since we're in "disable user on delete" mode and the user is inactive (disabled)
                    // the SCIM spec says to return a 404 in this case as though the user doesn't exist.
                    throw new NotFoundException(USER_NOT_FOUND);
                }
            }
        } else {
            // couldn't find the user in memory
            throw new NotFoundException(USER_NOT_FOUND + ": " + id);
        }
    }

    public boolean isPermanentlyDeleteUser()
    {
        return permanentlyDeleteUser;
    }

    public void setPermanentlyDeleteUser(boolean permanentlyDeleteUser)
    {
        this.permanentlyDeleteUser = permanentlyDeleteUser;
    }

    private void checkForConflict(AttributeMap attributeMap) throws ConflictException
    {
        // Retrieve the username from the attributes sent in the create request since it's a required attribute for
        // SCIM. We know if we got to this portion of the code then it's included.
        String newUserNameValue = attributeMap.getSingleValue(USERNAME);
        
        AttributeMap userEntry = ldapHelper.getEntry("cn=" + newUserNameValue, new String[] { ACTIVE }, BaseDn);

        if (userEntry != null) {
        	// We have an entry.
  
            // The username matches an existing one in memory. If we're in "permanentlyDeleteUser mode"
            // or if the existing user is active then throw a ConflictException. However, if we're in
            // "disable mode" and the user is inactive then allow them to create another user with the
            // same username but a different id.
            if (permanentlyDeleteUser || "true".equalsIgnoreCase(userEntry.getSingleValue(ACTIVE)))
            {
                // if we find a match and they're active then throw a ConflictException
                throw new ConflictException("User already exists: " + newUserNameValue);
            }
        }
    }

    private boolean isActive(String id)
    {
    	log.info("Checking user is active - id=" + id);
    	
        // Determine whether the user is active.
        AttributeMap userEntry = ldapHelper.getEntry("cn=" + id, new String[] { ACTIVE }, BaseDn);

        if (userEntry != null) {
        	return "true".equalsIgnoreCase(userEntry.getSingleValue(ACTIVE));
        }
        
        return false;
    }

    
    private AttributeMap userEntryToAttributeMap(AttributeMap userEntry) {
    
    	AttributeMap returnMap = new AttributeMap();
    	
    	try {
        for (Map.Entry<String, AttributeValue> e : userEntry.entrySet())
        {
        	log.info("Cleaning up: " + e.getKey());
        	
        	if (e.getKey().equalsIgnoreCase("createTimestamp")) {
        		returnMap.put(Constants.WHEN_CREATED, AttrValueSupport.make(StaticUtils.decodeGeneralizedTime(e.getValue().getValue())));
        	} else if (e.getKey().equalsIgnoreCase("modifyTimestamp")) {
        		returnMap.put(Constants.WHEN_CHANGED, AttrValueSupport.make(StaticUtils.decodeGeneralizedTime(e.getValue().getValue())));
        	} else if (e.getKey().equalsIgnoreCase("cn")) {
        		returnMap.put(Constants.ID, e.getValue().getValue());
        	} else {
        		returnMap.put(e.getKey(), e.getValue().getValue());
        	}
        }
    
    	} catch (Exception e) {
    		
    	}
    	
        return returnMap;
    }
    
    private String escapeCN(String cn) {
    	return cn.replace("+", "\\+");
    }
    
    private static String getRandomIntAsString()
    {
        Random rand = new Random();
        int randomNumber = rand.nextInt(100000) + 1;
        return Integer.toString(randomNumber);
    }

}
