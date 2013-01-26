/*
 * The MIT License
 * 
 * Copyright (c) 2012-2013 IKEDA Yasuyuki
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package jp.ikedam.ldap;

import java.io.UnsupportedEncodingException;
import java.util.Arrays;

import javax.naming.ldap.ExtendedResponse;

import java.util.logging.Logger;
import java.util.logging.Level;

/**
 * Response of LDAP "Who am i?" (RFC 4532)
 * 
 * @see LdapWhoamiRequest
 *
 */
public class LdapWhoamiResponse implements ExtendedResponse
{
    private static final long serialVersionUID = -7920991415681532204L;
    
    /**
     * enumuration to distinct the type of AuthzId.
     */
    public enum AuthzIdType
    {
        /**
         * Unknown type
         */
        UNKNOWN_AUTHZ_ID("unknown"),
        /**
         * Indicates the authzId is a distinguished name(DN), like uid=yourname,dc=example,dc=com.
         */
        DN_AUTHZ_ID("dn"),
        /**
         * Indicates the authzId is a user name, like yourname@example.com
         */
        U_AUTHZ_ID("u");
        
        private String name;
        private AuthzIdType(String name)
        {
            this.name = name;
        }
        
        /**
         * @inheritDoc
         */
        @Override
        public String toString(){
            return name;
        }
    }

    private String id;
    /**
     * Returns ResponseName(ID)
     * 
     * @return ResponseName of ExtendedResponse
     * @see javax.naming.ldap.ExtendedResponse#getID()
     */
    @Override
    public String getID()
    {
        return id;
    }
   
    
    private byte[] encodedValue;
    
    /**
     * Returns ResponseValue
     * 
     * @return ResponseValue of ExtendedResponse
     * @see javax.naming.ldap.ExtendedResponse#getEncodedValue()
     */
    @Override
    public byte[] getEncodedValue()
    {
        return encodedValue;
    }
    
    private String authzId;
    /**
     * Returns the authzId returned from the server
     * 
     * @return the authzId returned from the server
     */
    public String getAuthzId()
    {
        return authzId;
    }
    
    private AuthzIdType authzIdType = AuthzIdType.UNKNOWN_AUTHZ_ID;
    /**
     * Returns the type of authzId returned from the server
     * 
     * @return the authzIdType
     */
    public AuthzIdType getAuthzIdType()
    {
        return authzIdType;
    }
    
    private String dn = null;
    /**
     * Returns the distinguished name (DN) returned from the server.
     * 
     * Returns valid value only if getAuthzIdType() returns AuthzIdType.DN_AUTHZ_ID
     * 
     * @return the distinguished name (DN).
     */
    public String getDn()
    {
        return dn;
    }
    
    
    private String userid = null;
    /**
     * Returns the user id returned from the server.
     * 
     * Returns valid value only if getAuthzIdType() returns AuthzIdType.U_AUTHZ_ID
     * 
     * @return the user id.
     */
    public String getUserid()
    {
        return userid;
    }
    
    /**
     * Constructor
     * 
     * @param id ResponseName of ExtendedResponse
     * @param berValue ResponseValue of ExtendedResponse
     * @throws UnsupportedEncodingException 
     */
    public LdapWhoamiResponse(String id, byte[] berValue)
    {
        this.id = id;
        this.encodedValue = Arrays.copyOf(berValue, berValue.length);
        
        try
        {
            this.authzId = new String(berValue,"UTF-8");
        }
        catch (UnsupportedEncodingException e)
        {
            Logger logger = Logger.getLogger(getClass().getName());
            logger.log(Level.SEVERE, "Failed to decode LDAP who am i response", e);
            this.authzId = null;
            return;
        }
        if(this.authzId.startsWith("dn:"))
        {
            this.authzIdType = AuthzIdType.DN_AUTHZ_ID;
            this.dn = authzId.substring(3);
        }
        else if(authzId.startsWith("u:"))
        {
            this.authzIdType = AuthzIdType.U_AUTHZ_ID;
            this.userid = authzId.substring(2);
        }
    }
}
