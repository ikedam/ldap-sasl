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
package jp.ikedam.jenkins.plugins.ldap_sasl;

import java.util.Arrays;
import java.util.List;

import org.junit.Test;

import static org.junit.Assert.*;

/**
 * Tests for LdapSaslSecurityRealm not concerned with Jenkins.
 */
public class LdapSaslSecurityRealmSimpleTest
{
    @Test
    public void testLdapSaslSecurityRealm()
    {
        // Constructor parameters are preserved
        {
            List<String> ldapUriList = Arrays.asList("ldap:///", "ldaps:///");
            String mechanisms = "DIGEST-MD5 CRAM-MD5";
            UserDnResolver userDnResolver = new NoUserDnResolver();
            GroupResolver groupResolver = new NoGroupResolver();
            int connectionTimeout = 100;
            int readTimeout = 30;
            
            LdapSaslSecurityRealm target = new LdapSaslSecurityRealm(
                    ldapUriList,
                    mechanisms,
                    userDnResolver,
                    groupResolver,
                    connectionTimeout,
                    readTimeout
                    );
            assertEquals("Constructor parameters are preserved", ldapUriList, target.getLdapUriList());
            assertEquals("Constructor parameters are preserved", mechanisms, target.getMechanisms());
            assertSame("Constructor parameters are preserved", userDnResolver, target.getUserDnResolver());
            assertSame("Constructor parameters are preserved", groupResolver, target.getGroupResolver());
            assertEquals("Constructor parameters are preserved", connectionTimeout, target.getConnectionTimeout());
            assertEquals("Constructor parameters are preserved", readTimeout, target.getReadTimeout());
            
        }
        
        // Trimmed
        {
            LdapSaslSecurityRealm target = new LdapSaslSecurityRealm(
                    Arrays.asList("  ldap:///  ", "  ", "  ldaps:///  "),
                    "  ,  DIGEST-MD5   ,,,   CRAM-MD5  ,",
                    null,
                    null,
                    0,
                    0
                    );
            assertEquals("Trimmed", Arrays.asList("ldap:///", "ldaps:///"), target.getLdapUriList());
            assertEquals("Trimmed", "DIGEST-MD5 CRAM-MD5", target.getMechanisms());
        }
        
        // null
        {
            LdapSaslSecurityRealm target = new LdapSaslSecurityRealm(
                    null,
                    null,
                    null,
                    null,
                    0,
                    0
                    );
            assertEquals("null", 0, target.getLdapUriList().size());
            assertEquals("null", "", target.getMechanisms());
        }
    }
}
