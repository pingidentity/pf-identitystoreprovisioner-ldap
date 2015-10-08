package com.pingidentity.helper;

import java.util.Map;

import org.sourceid.saml20.adapter.attribute.AttrValueSupport;
import org.sourceid.saml20.adapter.attribute.AttributeValue;
import org.sourceid.saml20.domain.datasource.info.LdapInfo;
import org.sourceid.util.log.AttributeMap;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.ModificationItem;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
import javax.net.ssl.TrustManager;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.pingidentity.sdk.provision.Constants;
import com.unboundid.util.StaticUtils;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.List;

public class LdapHelper {

	private Log log = LogFactory.getLog(this.getClass());
	private Hashtable ldapEnvironment = new Hashtable();

    @SuppressWarnings({ "unchecked", "rawtypes" })
	public LdapHelper(LdapInfo ldapConnection) {

    	ldapEnvironment.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        //set security credentials, note using simple cleartext authentication
    	ldapEnvironment.put(Context.SECURITY_AUTHENTICATION, "simple");
    	ldapEnvironment.put(Context.SECURITY_PRINCIPAL, ldapConnection.getPrincipal());
    	ldapEnvironment.put(Context.SECURITY_CREDENTIALS, ldapConnection.getCredentials());
    	ldapEnvironment.put(Context.PROVIDER_URL, ldapConnection.getServerUrl());
	}

	public Boolean deleteEntry(String dn) {

    	log.debug("---[ deleteEntry ]------");
		
        try {

            //Create the initial directory context
            LdapContext ctx = new InitialLdapContext(ldapEnvironment, null);
            ctx.destroySubcontext(dn);
            ctx.close();
            
            return true;

        } catch (NamingException e) {
            System.err.println("Problem creating user: " + e);
        }
        
        return false;
	}
	
	public Boolean addEntry(String dn, AttributeMap defaultAttributes) {

    	log.debug("---[ addEntry ]------");
		
        try {

        	BasicAttributes attributesToAdd = new BasicAttributes();
        	
        	Attribute objectClass = new BasicAttribute("objectClass");
        	objectClass.add("top");
        	objectClass.add("person");  
            objectClass.add("organizationalPerson");  
            objectClass.add("inetOrgPerson");  
            
            attributesToAdd.put(objectClass);
        	
            for (Map.Entry<String, AttributeValue> e : defaultAttributes.entrySet())
            {
            	log.info("Creating user with attribute: " + e.getKey() + " -- " + e.getValue().getValue());

            	if (e.getKey().equalsIgnoreCase("whenCreated")) {
            		log.info("skipping");
            	} else if (e.getKey().equalsIgnoreCase("whenChanged")) {
            		log.info("skipping");
            	} else if (e.getKey().equalsIgnoreCase("userName")) {
            		log.info("skipping");
            	} else if (e.getKey().equalsIgnoreCase("id")) {
            		log.info("skipping");
            	} else {
            		attributesToAdd.put(new BasicAttribute(e.getKey(), e.getValue().getValue()));
            	}
            }
        	
            //Create the initial directory context
            LdapContext ctx = new InitialLdapContext(ldapEnvironment, null);

            ctx.createSubcontext(dn, attributesToAdd);  

            ctx.close();
            
            return true;

        } catch (NamingException e) {
            System.err.println("Problem creating user: " + e);
        }
        
        return false;
	}
	
	public Boolean modifyEntry(String dn, AttributeMap origAttributes, AttributeMap changedAttributes) {

    	log.debug("---[ modifyEntry ]------");
		
        try {

        	ArrayList<ModificationItem> attributesToMod = new ArrayList<ModificationItem>();
        	
        	
            for (Map.Entry<String, AttributeValue> e : changedAttributes.entrySet())
            {
            	log.info("Checking attribute: " + e.getKey() + " -- " + e.getValue().getValue());

            	if (e.getKey().equalsIgnoreCase("whenCreated")) {
            		log.info("skipping");
            	} else if (e.getKey().equalsIgnoreCase("whenChanged")) {
            		log.info("skipping");
            	} else if (e.getKey().equalsIgnoreCase("userName")) {
            		// compare to cn
            		if (!origAttributes.getSingleValue("cn").equals(e.getValue().getValue())) {
            			log.info("Modifying " + e.getKey() + " changing " + origAttributes.getSingleValue(e.getKey()) + " to " + e.getValue().getValue());
            			attributesToMod.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute("cn", e.getValue().getValue())));
            		}
            	} else if (e.getKey().equalsIgnoreCase("id")) {
            		log.info("skipping");
            	} else {
            		String originalValue = origAttributes.getSingleValue(e.getKey());
            		
            		if (originalValue != null) {
            			if (!originalValue.equals(e.getValue().getValue())) {
            				log.info("Modifying " + e.getKey() + " changing " + origAttributes.getSingleValue(e.getKey()) + " to " + e.getValue().getValue());
            				attributesToMod.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute(e.getKey(), e.getValue().getValue())));
            			}
            		} else {
        				log.info("Adding " + e.getKey() + " setting value to " + e.getValue().getValue());
        				attributesToMod.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute(e.getKey(), e.getValue().getValue())));
            		}
            	}
            }

            ModificationItem[] mods = new ModificationItem[attributesToMod.size()];
            mods = attributesToMod.toArray(mods);
            
            //Create the initial directory context
            LdapContext ctx = new InitialLdapContext(ldapEnvironment, null);
            ctx.modifyAttributes(dn, mods);
            ctx.close();
            
            return true;

        } catch (NamingException e) {
            System.err.println("Problem modifying user: " + e);
        }
        
        return false;
	}
	
    @SuppressWarnings({ "unchecked", "rawtypes" })
	public AttributeMap getEntry(String ldapFilter, String[] returnFields, String baseDn) {

    	log.debug("---[ getEntry ]------");

    	AttributeMap returnValues = new AttributeMap();
    	
        try {

            //Create the initial directory context
            LdapContext ctx = new InitialLdapContext(ldapEnvironment, null);

            //Create the search controls 		
            SearchControls userSearchCtls = new SearchControls();

            //Specify the search scope
            userSearchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);

            //Specify the attributes to return
            userSearchCtls.setReturningAttributes(returnFields);

            //Search for objects using the filter
            NamingEnumeration userAnswer = ctx.search(baseDn, ldapFilter, userSearchCtls);

            //Loop through the search results
            while (userAnswer.hasMoreElements()) {
                SearchResult sr = (SearchResult) userAnswer.next();
                Attributes attrs = sr.getAttributes();

                if (attrs != null) {
                    try {
                    	for (String thisAttrib : returnFields) {
                    		log.debug("Checking Attribute: " + thisAttrib);
                    		List<String> returnAV = new ArrayList<String>();
                    		
                        	Attribute returnedAttribute = attrs.get(thisAttrib);
                        	
                        	if (returnedAttribute != null) { // we have a value
                        		NamingEnumeration allValues = returnedAttribute.getAll();
                        		while (allValues.hasMore()) {
                        			String av = null;
                        			try {
                        				av = (String)allValues.next();
                        			} catch(Exception ex) {
                        				log.debug("Unable to convert attribute: " + returnedAttribute);
                        			}
                        			returnAV.add(av);
                        			log.debug("Adding Value: " + thisAttrib + " -> " + av);
                        		}
                        	} else {
                        		log.debug("Adding: " + thisAttrib + " -> null");
                        	}
                    		AttributeValue returnedAttributeValues = new AttributeValue(returnAV);
                    		returnValues.put(thisAttrib, returnedAttributeValues);
                    	}
                    } catch (Exception ex) {
                    	log.debug(ex.getMessage());
                 }
                 }
            }

            ctx.close();

        } catch (NamingException e) {
            log.info("Problem searching directory: " + e);
        }
        
        return returnValues;
    }

}
