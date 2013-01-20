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
package jp.ikedam.jenkins.plugins.ldap_sasl.ldap;

import java.util.Arrays;

import javax.naming.NamingException;
import javax.naming.ldap.ExtendedRequest;
import javax.naming.ldap.ExtendedResponse;

/**
 * Request to perform LDAP "Who am i?" (RFC 4532)
 * 
 * Use as following:
 * <code>
 *    InitialLdapContext ctx = blahblahblah;
 *    LdapWhoAmIResponse response = (LdapWhoAmIResponse)ctx.extendedOperation(new LdapWhoAmIRequest());
 *    switch(response.getAuthzIdType()){
 *    case LdapWhoamiResponse.AuthzIdType.DN_AUTHZ_ID:
 *        System.out.println(String.format("dn=%s", response.getDn());
 *        break;
 *    case LdapWhoamiResponse.AuthzIdType.U_AUTHZ_ID:
 *        System.out.println(String.format("userid=%s", response.getUserid());
 *        break;
 * </code>
 */
public class LdapWhoamiRequest implements ExtendedRequest
{
    private static final long serialVersionUID = -1089597514883298641L;
    
    
    /**
     * OID for LDAP "Who am i?"
     */
    private static final String OID = "1.3.6.1.4.1.4203.1.11.3";
    
    /**
     * Generate and return a response object.
     * 
     * Called when "Who am i" request is completed.
     * 
     * @param id        responseName of ExtendedResponse. In "Who am i?", this will be null (absent).
     * @param berValue  responseValue of ExtendedResponse. This will be authzId(RFC4513).
     * @param offset
     * @param length
     * @return response object.
     * @throws NamingException
     * @see javax.naming.ldap.ExtendedRequest#createExtendedResponse(java.lang.String, byte[], int, int)
     */
    @Override
    public ExtendedResponse createExtendedResponse(String id, byte[] berValue,
            int offset, int length) throws NamingException
    {
        return new LdapWhoamiResponse(id, Arrays.copyOfRange(berValue, offset, offset+length));
    }
    
    /**
     * Returns RequestValue
     * 
     * @return null for RequestValue field is absent.
     * @see javax.naming.ldap.ExtendedRequest#getEncodedValue()
     */
    @Override
    public byte[] getEncodedValue()
    {
        return null;
    }
    
    /**
     * Returns OID
     * 
     * @return OID for LDAP "who am i?"
     * @see javax.naming.ldap.ExtendedRequest#getID()
     */
    @Override
    public String getID()
    {
        return OID;
    }
    
}
